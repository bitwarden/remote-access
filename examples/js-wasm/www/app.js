import { createClient } from "./remote-access.js";
import Alpine from "alpinejs";

// Kept outside Alpine's reactive scope to avoid Proxy wrapping,
// which breaks JS private class fields (#inner) in RemoteAccessClient.
let client = null;

window.app = function () {
  return {
    proxyUrl: "wss://ap.lesspassword.dev",
    editingProxy: false,
    connections: [],
    loading: true,
    connected: false,
    connectedLabel: "",
    showPairForm: false,
    token: "",
    domain: "",
    credential: null,
    pairing: false,
    requesting: false,
    log: [],

    _initialized: false,
    async init() {
      if (this._initialized) return;
      this._initialized = true;
      await this.refreshConnections();
    },

    addLog(msg, type = "info") {
      const time = new Date().toLocaleTimeString("en-US", { hour12: false });
      const last = this.log[this.log.length - 1];
      if (type !== "pending" && last?.type === "pending") {
        last.msg = msg;
        last.type = type;
        last.time = time;
      } else {
        this.log.push({ time, msg, type });
      }
      this.$nextTick(() => {
        const el = this.$refs.log;
        if (el) el.scrollTop = el.scrollHeight;
      });
    },

    async refreshConnections() {
      this.loading = true;
      try {
        const tmp = await createClient(this.proxyUrl);
        this.connections = await tmp.listConnections();
        this.addLog(
          this.connections.length
            ? `Loaded ${this.connections.length} saved connection(s)`
            : "Ready — no saved connections",
        );
      } catch (e) {
        this.connections = [];
        this.addLog(`Failed to load connections: ${e}`, "error");
      } finally {
        this.loading = false;
      }
    },

    connLabel(conn) {
      return conn.name || conn.fingerprint.substring(0, 16) + "...";
    },

    connDate(conn) {
      return conn.lastConnectedAt
        ? new Date(conn.lastConnectedAt * 1000).toLocaleDateString()
        : "never";
    },

    async pair() {
      if (!this.token.trim()) {
        this.addLog("Enter a pairing token", "error");
        return;
      }
      this.pairing = true;
      this.addLog(`Pairing with ${this.token.substring(0, 11)}...`, "pending");
      try {
        client = await createClient(this.proxyUrl);
        const fp = await client.pair(this.token.trim());
        this.addLog(fp ? `Paired. Fingerprint: ${fp.substring(0, 12)}...` : "Paired via PSK", "success");
        this.connected = true;
        this.connectedLabel = "Connected — new session";
        this.showPairForm = false;
        this.token = "";
        await this.refreshConnections();
      } catch (e) {
        this.addLog(`Pairing failed: ${e}`, "error");
        client?.disconnect();
        client = null;
      } finally {
        this.pairing = false;
      }
    },

    async reconnect(fingerprint) {
      this.addLog(`Reconnecting to ${fingerprint.substring(0, 12)}...`, "pending");
      try {
        client = await createClient(this.proxyUrl);
        await client.reconnect(fingerprint);
        this.addLog("Reconnected", "success");
        this.connected = true;
        this.connectedLabel = `Connected — ${fingerprint.substring(0, 12)}...`;
        await this.refreshConnections();
      } catch (e) {
        this.addLog(`Reconnect failed: ${e}`, "error");
        client?.disconnect();
        client = null;
      }
    },

    disconnect() {
      client?.disconnect();
      client = null;
      this.connected = false;
      this.credential = null;
      this.addLog("Disconnected");
    },

    async requestCredential() {
      if (!this.domain.trim()) return;
      this.requesting = true;
      this.addLog(`Requesting credential for ${this.domain}...`, "pending");
      try {
        this.credential = await client.getCredential(this.domain.trim());
        this.addLog(`Credential received for ${this.domain}`, "success");
      } catch (e) {
        this.addLog(`Request failed: ${e}`, "error");
      } finally {
        this.requesting = false;
      }
    },

    async clearConnections() {
      try {
        const tmp = await createClient(this.proxyUrl);
        tmp.clearConnections();
        this.addLog("Cleared all cached connections");
      } catch (e) {
        this.addLog(`Failed to clear: ${e}`, "error");
      }
      await this.refreshConnections();
    },

    credentialEntries() {
      if (!this.credential) return [];
      return Object.entries(this.credential).filter(([, v]) => v != null);
    },

    saveProxy() {
      this.editingProxy = false;
    },
  };
};

window.Alpine = Alpine;
Alpine.start();
