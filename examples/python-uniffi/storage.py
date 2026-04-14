"""In-memory storage implementations for UniFFI examples."""

from ap_uniffi import ConnectionStorage, FfiStoredConnection, IdentityStorage


class MemoryIdentityStorage(IdentityStorage):
    """In-memory identity storage — keypair lives only for the process lifetime."""

    def __init__(self):
        self._data = None

    def load_identity(self) -> bytes | None:
        return self._data

    def save_identity(self, identity_bytes: bytes):
        self._data = identity_bytes


class MemoryConnectionStorage(ConnectionStorage):
    """In-memory connection storage — connections live only for the process lifetime."""

    def __init__(self):
        self._connections: list[FfiStoredConnection] = []

    def get(self, fingerprint_hex: str) -> FfiStoredConnection | None:
        for c in self._connections:
            if c.fingerprint == fingerprint_hex:
                return c
        return None

    def save(self, connection: FfiStoredConnection):
        self._connections = [c for c in self._connections if c.fingerprint != connection.fingerprint]
        self._connections.append(connection)

    def update(self, fingerprint_hex: str, last_connected_at: int):
        for c in self._connections:
            if c.fingerprint == fingerprint_hex:
                c.last_connected_at = last_connected_at

    def list(self) -> list[FfiStoredConnection]:
        return list(self._connections)
