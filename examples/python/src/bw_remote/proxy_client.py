"""WebSocket proxy client — authentication, rendezvous, and messaging.

Reference: crates/bw-proxy-client/src/protocol_client.rs

The Rust proxy uses serde_json with untagged enum serialization for Messages.
Wire format examples:
  {"AuthChallenge": [n1, n2, ..., n32]}
  {"AuthResponse": [{"cose_key_bytes": [...]}, {"cose_sign1_bytes": [...]}]}
  "GetRendevouz"
  {"GetIdentity": {"code": "ABC-DEF-GHI"}}
  {"RendevouzInfo": {"code": "ABC-DEF-GHI"}}
  {"IdentityInfo": {"fingerprint": [...], "identity": {"cose_key_bytes": [...]}}}
  {"Send": {"destination": [...], "payload": [...]}}

UPDATE: The Rust Messages enum uses serde default (externally tagged), so:
  AuthChallenge → {"AuthChallenge": [32 ints]}
  AuthResponse  → {"AuthResponse": [identity_obj, response_obj]}
  Send          → {"Send": {"source": null|[...], "destination": [...], "payload": [...]}}
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass

import websockets

from .errors import AuthenticationError, RemoteAccessError
from .identity import IdentityKeyPair

logger = logging.getLogger(__name__)


@dataclass
class SendMessage:
    """A Send message received from the proxy."""

    source: bytes  # 32-byte fingerprint
    destination: bytes  # 32-byte fingerprint
    payload: bytes  # raw bytes


@dataclass
class IdentityInfoMessage:
    """An IdentityInfo message received from the proxy."""

    fingerprint: bytes  # 32-byte fingerprint
    identity_cose_bytes: bytes  # COSE key bytes


class ProxyClient:
    """Async WebSocket client for the bw-proxy server."""

    def __init__(self, proxy_url: str, identity: IdentityKeyPair) -> None:
        self._proxy_url = proxy_url
        self._identity = identity
        self._ws: websockets.WebSocketClientProtocol | None = None
        self._incoming: asyncio.Queue = asyncio.Queue()
        self._read_task: asyncio.Task | None = None

    async def connect(self) -> None:
        """Connect to the proxy and complete challenge-response auth."""
        logger.debug("Connecting to %s", self._proxy_url)
        self._ws = await websockets.connect(self._proxy_url)

        # Phase 1: Authentication
        # Receive AuthChallenge
        raw = await asyncio.wait_for(self._ws.recv(), timeout=5.0)
        msg = json.loads(raw)

        if "AuthChallenge" not in msg:
            raise AuthenticationError(f"Expected AuthChallenge, got: {list(msg.keys())}")

        challenge_ints = msg["AuthChallenge"]
        challenge = bytes(challenge_ints)

        # Sign challenge and send AuthResponse
        identity_obj = {"cose_key_bytes": list(self._identity.identity().cose_key_bytes())}
        cose_sign1 = self._identity.sign_challenge(challenge)
        response_obj = {"cose_sign1_bytes": list(cose_sign1)}

        auth_response = {"AuthResponse": [identity_obj, response_obj]}
        await self._ws.send(json.dumps(auth_response))

        logger.debug("Authentication complete")

        # Start background read task
        self._read_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        """Background task dispatching incoming messages."""
        assert self._ws is not None
        try:
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                    await self._dispatch(msg)
                except Exception:
                    logger.exception("Error dispatching message")
        except websockets.ConnectionClosed:
            logger.debug("WebSocket connection closed")

    async def _dispatch(self, msg: dict | str) -> None:
        """Route parsed JSON messages to the incoming queue."""
        if isinstance(msg, str):
            # Unit variant like "GetRendevouz" — not expected from server
            return

        if "Send" in msg:
            send = msg["Send"]
            source_ints = send.get("source")
            if source_ints is None:
                return
            source = bytes(source_ints)
            destination = bytes(send["destination"])
            payload = bytes(send["payload"])
            await self._incoming.put(
                SendMessage(source=source, destination=destination, payload=payload)
            )
        elif "RendevouzInfo" in msg:
            info = msg["RendevouzInfo"]
            code = info["code"] if isinstance(info, dict) else info
            await self._incoming.put(("rendezvous_info", code))
        elif "IdentityInfo" in msg:
            info = msg["IdentityInfo"]
            fp = bytes(info["fingerprint"])
            cose_bytes = bytes(info["identity"]["cose_key_bytes"])
            await self._incoming.put(
                IdentityInfoMessage(fingerprint=fp, identity_cose_bytes=cose_bytes)
            )
        else:
            logger.debug("Unhandled message type: %s", list(msg.keys()))

    async def send_to(self, destination: bytes, payload: bytes) -> None:
        """Send a message to another client via the proxy."""
        if self._ws is None:
            raise RemoteAccessError("Not connected")

        msg = {
            "Send": {
                "destination": list(destination),
                "payload": list(payload),
            }
        }
        await self._ws.send(json.dumps(msg))

    async def request_identity(self, rendezvous_code: str) -> None:
        """Send GetIdentity request for a rendezvous code."""
        if self._ws is None:
            raise RemoteAccessError("Not connected")

        msg = {"GetIdentity": {"code": rendezvous_code}}
        await self._ws.send(json.dumps(msg))

    async def request_rendezvous(self) -> None:
        """Request a rendezvous code from the server."""
        if self._ws is None:
            raise RemoteAccessError("Not connected")

        await self._ws.send(json.dumps("GetRendevouz"))

    async def recv(self, timeout: float | None = None) -> SendMessage | IdentityInfoMessage | tuple:
        """Receive the next incoming message."""
        return await asyncio.wait_for(self._incoming.get(), timeout=timeout)

    async def disconnect(self) -> None:
        """Close the WebSocket connection."""
        if self._read_task is not None:
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass
            self._read_task = None

        if self._ws is not None:
            await self._ws.close()
            self._ws = None
