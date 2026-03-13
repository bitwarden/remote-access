"""Session persistence for cached connections.

Reference: crates/bw-remote/src/storage/session_storage.rs

Session cache files: ~/.bw-remote/session_cache_{name}.json
Identity key files: ~/.bw-remote/{name}.key
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import cbor2

from .packet import CiphersuiteId
from .transport import MultiDeviceTransport


@dataclass
class SessionRecord:
    """A cached session entry, compatible with the Rust CLI format."""

    remote_fingerprint: list[int]  # 32-byte fingerprint as int array
    cached_at: int = 0
    last_connected_at: int = 0
    transport_state: list[int] | None = None  # CBOR bytes as int array
    name: str | None = None


class SessionStore:
    """File-based session cache at ~/.bw-remote/session_cache_{name}.json."""

    def __init__(self, cache_name: str, base_dir: Path | None = None) -> None:
        if base_dir is None:
            base_dir = Path.home() / ".bw-remote"
        base_dir.mkdir(parents=True, exist_ok=True)
        self._path = base_dir / f"session_cache_{cache_name}.json"
        self._sessions: list[SessionRecord] = []
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            data = json.loads(self._path.read_text())
            self._sessions = []
            for s in data.get("sessions", []):
                self._sessions.append(SessionRecord(
                    remote_fingerprint=s["remote_fingerprint"],
                    cached_at=s.get("cached_at", 0),
                    last_connected_at=s.get("last_connected_at", 0),
                    transport_state=s.get("transport_state"),
                    name=s.get("name"),
                ))

    def _save(self) -> None:
        sessions = []
        for s in self._sessions:
            rec: dict = {
                "remote_fingerprint": s.remote_fingerprint,
                "cached_at": s.cached_at,
                "last_connected_at": s.last_connected_at,
            }
            if s.transport_state is not None:
                rec["transport_state"] = s.transport_state
            if s.name is not None:
                rec["name"] = s.name
            sessions.append(rec)
        self._path.write_text(json.dumps({"sessions": sessions}, indent=2))

    def _fp_to_list(self, fingerprint: bytes) -> list[int]:
        return list(fingerprint)

    def _find(self, fingerprint: bytes) -> SessionRecord | None:
        fp_list = self._fp_to_list(fingerprint)
        for s in self._sessions:
            if s.remote_fingerprint == fp_list:
                return s
        return None

    def has_session(self, fingerprint: bytes) -> bool:
        return self._find(fingerprint) is not None

    def cache_session(self, fingerprint: bytes) -> None:
        now = int(time.time())
        existing = self._find(fingerprint)
        if existing is not None:
            existing.cached_at = now
        else:
            self._sessions.append(SessionRecord(
                remote_fingerprint=self._fp_to_list(fingerprint),
                cached_at=now,
                last_connected_at=now,
            ))
        self._save()

    def save_transport_state(self, fingerprint: bytes, transport: MultiDeviceTransport) -> None:
        """Save transport state as CBOR bytes (compatible with Rust PersistentTransportState)."""
        existing = self._find(fingerprint)
        if existing is None:
            raise ValueError("Session not found")

        # Serialize as CBOR array matching Rust's ciborium struct serialization order:
        # [ciphersuite, send_key, recv_key, send_rekey_counter, recv_rekey_counter,
        #  last_rekeyed_time, rekey_interval]
        state_cbor = cbor2.dumps([
            transport.ciphersuite.value,
            transport.send_key,
            transport.recv_key,
            transport.send_rekey_counter,
            transport.recv_rekey_counter,
            transport.last_rekeyed_time,
            transport.rekey_interval,
        ])
        existing.transport_state = list(state_cbor)
        self._save()

    def load_transport_state(self, fingerprint: bytes) -> MultiDeviceTransport | None:
        """Load transport state from the session cache."""
        existing = self._find(fingerprint)
        if existing is None or existing.transport_state is None:
            return None

        state_bytes = bytes(existing.transport_state)
        arr = cbor2.loads(state_bytes)
        return MultiDeviceTransport(
            ciphersuite=CiphersuiteId(arr[0]),
            send_key=bytes(arr[1]),
            recv_key=bytes(arr[2]),
            send_rekey_counter=arr[3],
            recv_rekey_counter=arr[4],
            last_rekeyed_time=arr[5],
            rekey_interval=arr[6],
        )

    def update_last_connected(self, fingerprint: bytes) -> None:
        existing = self._find(fingerprint)
        if existing is not None:
            existing.last_connected_at = int(time.time())
            self._save()

    def list_sessions(self) -> list[tuple[bytes, str | None, int, int]]:
        """Return (fingerprint, name, cached_at, last_connected_at) tuples."""
        result = []
        for s in self._sessions:
            fp = bytes(s.remote_fingerprint)
            result.append((fp, s.name, s.cached_at, s.last_connected_at))
        return result

    def remove_session(self, fingerprint: bytes) -> None:
        fp_list = self._fp_to_list(fingerprint)
        self._sessions = [s for s in self._sessions if s.remote_fingerprint != fp_list]
        self._save()

    def clear(self) -> None:
        self._sessions.clear()
        self._save()
