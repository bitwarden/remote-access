import ApUniffi
import Foundation

struct Arguments {
    let token: String
    let domain: String
    let proxyUrl: String
}

func parseArguments() -> Arguments? {
    let args = CommandLine.arguments
    var token: String?
    var domain: String?
    var proxyUrl = "wss://ap.lesspassword.dev"

    var i = 1
    while i < args.count {
        switch args[i] {
        case "--token", "--domain", "--proxy":
            let flag = args[i]
            i += 1
            guard i < args.count else {
                fputs("\(flag) requires a value\n", stderr)
                return nil
            }
            switch flag {
            case "--token": token = args[i]
            case "--domain": domain = args[i]
            case "--proxy": proxyUrl = args[i]
            default: break
            }
        default:
            fputs("Unknown argument: \(args[i])\n", stderr)
            return nil
        }
        i += 1
    }

    guard let token = token, let domain = domain else {
        fputs("Usage: ApUniffiExample --token <TOKEN> --domain <DOMAIN> [--proxy <URL>]\n", stderr)
        return nil
    }

    return Arguments(token: token, domain: domain, proxyUrl: proxyUrl)
}

func main() async -> Int32 {
    guard let args = parseArguments() else {
        return 1
    }

    do {
        let client = try RemoteAccessClient(
            proxyUrl: args.proxyUrl,
            identityStorage: MemoryIdentityStorage(),
            connectionStorage: MemoryConnectionStorage(),
            eventHandler: nil
        )

        try await client.connect()

        if looksLikePskToken(token: args.token) {
            try await client.pairWithPsk(pskToken: args.token)
        } else {
            let fp = try await client.pairWithHandshake(code: args.token)
            fputs("Handshake fingerprint: \(fp)\n", stderr)
        }

        let cred = try await client.requestCredential(domain: args.domain)
        client.close()

        if let username = cred.username { print("Username: \(username)") }
        if let password = cred.password { print("Password: \(password)") }
        if let totp = cred.totp { print("TOTP: \(totp)") }
        if let uri = cred.uri { print("URI: \(uri)") }
        if let notes = cred.notes { print("Notes: \(notes)") }

        return 0
    } catch {
        fputs("Error: \(error)\n", stderr)
        return 1
    }
}

exit(await main())
