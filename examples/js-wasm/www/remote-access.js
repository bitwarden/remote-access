/**
 * Bitwarden Remote Access — WASM client wrapper.
 *
 * Simple API for pairing with a trusted device and requesting credentials.
 *
 * Usage:
 *   import { createClient } from "./remote-access.js";
 *
 *   const client = await createClient("wss://ap.lesspassword.dev");
 *
 *   // Pair with a new device
 *   await client.pair("ABC-DEF-GHI");
 *
 *   // Or reconnect to a saved session
 *   await client.reconnect(fingerprint);
 *
 *   // Request a credential
 *   const cred = await client.getCredential("example.com");
 *   console.log(cred.username, cred.password);
 *
 *   // List / clear saved connections
 *   const connections = await client.listConnections();
 *   client.clearConnections();
 *
 *   // Disconnect
 *   client.disconnect();
 */

import wasmInit, {
  WasmRemoteClient,
  listConnections,
  clearConnections,
} from "../pkg/bw_remote_wasm.js";

let wasmReady = false;

async function ensureWasm() {
  if (!wasmReady) {
    await wasmInit();
    wasmReady = true;
  }
}

/** Cheap heuristic matching PskToken::looks_like_psk_token in Rust. */
function looksLikePskToken(s) {
  return s.length === 129 && s[64] === "_";
}

/** Extract a human-readable message from WASM/JS errors. */
function cleanError(e) {
  if (e instanceof Error) return e.message;
  const s = String(e);
  // Strip "Failed to connect to proxy: Failed to create WebSocket: JsValue(...)" noise
  const jsVal = s.match(/JsValue\((?:\w+:\s*)?(.+?)(?:\s+\S+@http).*/s);
  if (jsVal) return jsVal[1].trim();
  // Strip nested "Foo: Bar: Baz" to just the innermost message
  const parts = s.split(/:\s+/);
  return parts[parts.length - 1].trim() || s;
}

/**
 * Create a remote access client.
 *
 * @param {string} proxyUrl - WebSocket URL of the proxy server
 * @param {string} [identityName="js-wasm-remote"] - Name for the localStorage identity
 * @returns {Promise<RemoteAccessClient>}
 */
export async function createClient(proxyUrl, identityName = "js-wasm-remote") {
  await ensureWasm();
  return new RemoteAccessClient(proxyUrl, identityName);
}

class RemoteAccessClient {
  #inner = null;
  #proxyUrl;
  #identityName;

  constructor(proxyUrl, identityName) {
    if (!proxyUrl || !/^wss?:\/\/.+/.test(proxyUrl)) {
      throw new Error(`Invalid proxy URL: "${proxyUrl}" — expected ws:// or wss://`);
    }
    this.#proxyUrl = proxyUrl;
    this.#identityName = identityName;
  }

  /**
   * Pair with a new device using a rendezvous code or PSK token.
   * @param {string} token - Rendezvous code (e.g. "ABC-DEF-GHI") or PSK token
   * @returns {Promise<string|null>} Handshake fingerprint for rendezvous, null for PSK
   */
  async pair(token) {
    return this.#withFreshConnection((inner) =>
      looksLikePskToken(token)
        ? inner.pairWithPsk(token).then(() => null)
        : inner.pairWithHandshake(token),
    );
  }

  /**
   * Reconnect to a previously paired device.
   * @param {string} fingerprint - Hex fingerprint of the cached session
   */
  async reconnect(fingerprint) {
    return this.#withFreshConnection((inner) =>
      inner.loadCachedConnection(fingerprint),
    );
  }

  async #withFreshConnection(action) {
    this.disconnect();
    this.#inner = new WasmRemoteClient(this.#proxyUrl, this.#identityName);
    try {
      await this.#inner.connect();
      return await action(this.#inner);
    } catch (e) {
      this.#inner.close();
      this.#inner = null;
      throw new Error(cleanError(e));
    }
  }

  /**
   * Request a credential by domain.
   * @param {string} domain - e.g. "example.com"
   * @returns {Promise<{username?, password?, totp?, uri?, notes?, credential_id?, domain?}>}
   */
  async getCredential(domain) {
    if (!this.#inner) throw new Error("Not connected — call pair() or reconnect() first");
    try {
      const cred = await this.#inner.requestCredential(domain);
      return cred.toJSON();
    } catch (e) {
      throw new Error(cleanError(e));
    }
  }

  /** List saved connections from localStorage. */
  async listConnections() {
    return listConnections(this.#identityName);
  }

  /** Clear all saved connections from localStorage. */
  clearConnections() {
    clearConnections(this.#identityName);
  }

  /** Disconnect and release resources. */
  disconnect() {
    if (this.#inner) {
      this.#inner.close();
      this.#inner = null;
    }
  }

}
