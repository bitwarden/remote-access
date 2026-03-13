"""RemoteClient — main entry point for connecting and requesting credentials.

Reference: crates/bw-rat-client/src/clients/remote_client.rs

Flow:
  1. Load/generate identity
  2. Connect to proxy, authenticate
  3. Resolve rendezvous code (or use cached session / PSK)
  4. Noise NNpsk2 handshake as initiator
  5. Request credentials over encrypted channel
"""

from __future__ import annotations

import asyncio
import base64
import logging

from .errors import (
    CredentialRequestError,
    HandshakeError,
    RemoteAccessError,
    SessionNotFoundError,
)
from .identity import IdentityKeyPair, load_or_generate_identity
from .noise_handshake import InitiatorHandshake
from .packet import CiphersuiteId, HandshakePacket, TransportPacket
from .protocol_messages import (
    CredentialData,
    make_credential_request,
    make_credential_request_payload,
    make_handshake_init,
    parse_credential_response_payload,
    parse_protocol_message,
)
from .proxy_client import IdentityInfoMessage, ProxyClient, SendMessage
from .psk import Psk
from .session_store import SessionStore
from .transport import MultiDeviceTransport

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0


class RemoteClient:
    """High-level remote client for connecting and requesting credentials.

    Usage:
        client = RemoteClient(proxy_url="ws://localhost:8080")
        await client.connect(token="ABC-DEF-GHI")
        cred = await client.request_credential("example.com")
        await client.close()
    """

    def __init__(
        self,
        proxy_url: str = "ws://localhost:8080",
        identity_name: str = "python-remote",
    ) -> None:
        self._proxy_url = proxy_url
        self._identity_name = identity_name
        self._identity: IdentityKeyPair | None = None
        self._proxy: ProxyClient | None = None
        self._transport: MultiDeviceTransport | None = None
        self._remote_fingerprint: bytes | None = None
        self._session_store: SessionStore | None = None

    async def connect(
        self,
        token: str | None = None,
        session: str | None = None,
        verify_fingerprint: bool = False,
    ) -> str:
        """Connect to a listening peer.

        Args:
            token: Rendezvous code ("ABC-DEF-GHI") or PSK token
                   ("<64hex_psk>_<64hex_fingerprint>").
            session: Hex fingerprint of a cached session to reconnect to.
            verify_fingerprint: If True, return the handshake fingerprint for
                                out-of-band verification (caller should verify).

        Returns:
            Handshake fingerprint (6-char hex string), or empty string for
            cached sessions.
        """
        # Load or generate identity
        self._identity = load_or_generate_identity(self._identity_name)
        self._session_store = SessionStore(self._identity_name)

        # Connect to proxy and authenticate
        self._proxy = ProxyClient(self._proxy_url, self._identity)
        await self._proxy.connect()

        logger.info(
            "Connected to proxy, identity fingerprint: %s",
            self._identity.identity().fingerprint_hex(),
        )

        if session is not None:
            # Cached session reconnection
            return await self._connect_cached(session)
        elif token is not None:
            if "_" in token and len(token) == 129:
                # PSK token format: <64hex_psk>_<64hex_fingerprint>
                return await self._connect_psk(token)
            else:
                # Rendezvous code
                return await self._connect_rendezvous(token)
        else:
            # Auto-select: use single cached session if exactly one exists
            sessions = self._session_store.list_sessions()
            if len(sessions) == 1:
                fp_hex = sessions[0][0].hex()
                return await self._connect_cached(fp_hex)
            elif len(sessions) > 1:
                raise RemoteAccessError(
                    f"Multiple cached sessions ({len(sessions)}), "
                    "specify --session <fingerprint> to disambiguate"
                )
            else:
                raise RemoteAccessError(
                    "No token or cached session provided. "
                    "Use --token <code> or --session <fingerprint>"
                )

    async def _connect_rendezvous(self, code: str) -> str:
        """Connect via rendezvous code."""
        assert self._proxy is not None

        logger.info("Resolving rendezvous code: %s", code)
        await self._proxy.request_identity(code)

        # Wait for IdentityInfo response
        msg = await self._proxy.recv(timeout=10.0)
        if not isinstance(msg, IdentityInfoMessage):
            raise HandshakeError(f"Expected IdentityInfo, got {type(msg).__name__}")

        remote_fingerprint = msg.fingerprint
        logger.info("Resolved to fingerprint: %s", remote_fingerprint.hex())

        # Perform Noise handshake (no PSK)
        fingerprint = await self._perform_handshake(remote_fingerprint, psk=None)

        # Cache session
        assert self._session_store is not None
        self._session_store.cache_session(remote_fingerprint)
        if self._transport is not None:
            self._session_store.save_transport_state(remote_fingerprint, self._transport)

        return fingerprint

    async def _connect_psk(self, token: str) -> str:
        """Connect via PSK token."""
        psk_hex, fp_hex = token.split("_", 1)
        psk = Psk.from_hex(psk_hex)
        remote_fingerprint = bytes.fromhex(fp_hex)

        logger.info("PSK mode, target fingerprint: %s", fp_hex)

        fingerprint = await self._perform_handshake(remote_fingerprint, psk=psk)

        # Cache session
        assert self._session_store is not None
        self._session_store.cache_session(remote_fingerprint)
        if self._transport is not None:
            self._session_store.save_transport_state(remote_fingerprint, self._transport)

        return fingerprint

    async def _connect_cached(self, fp_hex: str) -> str:
        """Reconnect using a cached session."""
        assert self._session_store is not None
        remote_fingerprint = bytes.fromhex(fp_hex)

        transport = self._session_store.load_transport_state(remote_fingerprint)
        if transport is None:
            raise SessionNotFoundError(f"No cached session for {fp_hex}")

        self._transport = transport
        self._remote_fingerprint = remote_fingerprint
        self._session_store.update_last_connected(remote_fingerprint)

        logger.info("Reconnected to cached session: %s", fp_hex)
        return ""

    async def _perform_handshake(
        self,
        remote_fingerprint: bytes,
        psk: Psk | None,
    ) -> str:
        """Perform Noise NNpsk2 handshake as initiator."""
        assert self._proxy is not None

        handshake = InitiatorHandshake(psk=psk)

        # Send HandshakeInit
        init_packet = handshake.send_start()
        init_b64 = base64.b64encode(init_packet.encode()).decode()
        init_msg = make_handshake_init(init_b64, handshake.ciphersuite_str)
        await self._proxy.send_to(remote_fingerprint, init_msg.encode())

        logger.debug("Sent handshake init")

        # Wait for HandshakeResponse
        response_data: str | None = None
        deadline = asyncio.get_event_loop().time() + 10.0
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            try:
                msg = await self._proxy.recv(timeout=max(0.1, remaining))
            except asyncio.TimeoutError:
                break

            if isinstance(msg, SendMessage):
                try:
                    text = msg.payload.decode("utf-8")
                    parsed = parse_protocol_message(text)
                    if parsed.get("type") == "handshake-response":
                        response_data = parsed["data"]
                        break
                except (UnicodeDecodeError, ValueError, KeyError):
                    continue

        if response_data is None:
            raise HandshakeError("Timeout waiting for handshake response")

        # Decode and process response
        response_bytes = base64.b64decode(response_data)
        response_packet = HandshakePacket.decode(response_bytes)

        handshake.receive_finish(response_packet)
        send_key, recv_key, fingerprint = handshake.finalize()

        # Create transport
        self._transport = MultiDeviceTransport(
            ciphersuite=CiphersuiteId.CLASSICAL,
            send_key=send_key,
            recv_key=recv_key,
        )
        self._remote_fingerprint = remote_fingerprint

        logger.info("Handshake complete, fingerprint: %s", fingerprint)
        return fingerprint

    async def request_credential(
        self,
        domain: str,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> CredentialData:
        """Request a credential for the given domain.

        Args:
            domain: The domain to request credentials for.
            timeout: Timeout in seconds.

        Returns:
            CredentialData with username, password, etc.
        """
        if self._transport is None or self._proxy is None or self._remote_fingerprint is None:
            raise RemoteAccessError("Not connected — call connect() first")

        # Build and encrypt credential request
        payload_json, request_id = make_credential_request_payload(domain)
        encrypted_packet = self._transport.encrypt(payload_json.encode())
        encrypted_b64 = base64.b64encode(encrypted_packet.encode()).decode()

        # Wrap in ProtocolMessage and send
        msg_json = make_credential_request(encrypted_b64)
        await self._proxy.send_to(self._remote_fingerprint, msg_json.encode())

        logger.debug("Sent credential request for %s (id=%s)", domain, request_id)

        # Wait for credential response
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            try:
                msg = await self._proxy.recv(timeout=max(0.1, remaining))
            except asyncio.TimeoutError:
                break

            if isinstance(msg, SendMessage):
                try:
                    text = msg.payload.decode("utf-8")
                    parsed = parse_protocol_message(text)
                    if parsed.get("type") == "credential-response":
                        encrypted_b64 = parsed["encrypted"]
                        encrypted_bytes = base64.b64decode(encrypted_b64)
                        packet = TransportPacket.decode(encrypted_bytes)
                        decrypted = self._transport.decrypt(packet)

                        cred, error, resp_id = parse_credential_response_payload(decrypted)

                        if resp_id != request_id:
                            # Not our response, keep waiting
                            continue

                        if error:
                            raise CredentialRequestError(error)
                        if cred is None:
                            raise CredentialRequestError(
                                "Response contains neither credential nor error"
                            )
                        return cred
                except CredentialRequestError:
                    raise
                except Exception as e:
                    logger.warning("Error processing response: %s", e)
                    continue

        raise CredentialRequestError(
            f"Timeout waiting for credential response for {domain}"
        )

    async def close(self) -> None:
        """Close the connection and save session state."""
        if (
            self._session_store is not None
            and self._remote_fingerprint is not None
            and self._transport is not None
        ):
            try:
                self._session_store.save_transport_state(
                    self._remote_fingerprint, self._transport
                )
            except Exception:
                logger.warning("Failed to save transport state", exc_info=True)

        if self._proxy is not None:
            await self._proxy.disconnect()
            self._proxy = None

        self._transport = None
        self._remote_fingerprint = None
