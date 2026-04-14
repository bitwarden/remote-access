import ApUniffi
import Foundation

/// In-memory identity storage — keypair lives only for the process lifetime.
class MemoryIdentityStorage: IdentityStorage {
    private var data: Data?

    func loadIdentity() -> Data? { data }
    func saveIdentity(identityBytes: Data) throws { data = identityBytes }
}

/// In-memory connection storage — connections live only for the process lifetime.
class MemoryConnectionStorage: ConnectionStorage {
    private var connections: [FfiStoredConnection] = []

    func get(fingerprintHex: String) -> FfiStoredConnection? {
        connections.first { $0.fingerprint == fingerprintHex }
    }

    func save(connection: FfiStoredConnection) throws {
        connections.removeAll { $0.fingerprint == connection.fingerprint }
        connections.append(connection)
    }

    func update(fingerprintHex: String, lastConnectedAt: UInt64) throws {
        if let i = connections.firstIndex(where: { $0.fingerprint == fingerprintHex }) {
            var c = connections[i]
            c.lastConnectedAt = lastConnectedAt
            connections[i] = c
        }
    }

    func list() -> [FfiStoredConnection] { connections }
}
