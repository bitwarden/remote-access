import ApUniffi
import Foundation

func main() -> Int32 {
    let args = CommandLine.arguments

    guard args.count >= 3 else {
        fputs("Usage: ApUniffiExample --token <TOKEN> --domain <DOMAIN> [--proxy <URL>]\n", stderr)
        return 1
    }

    var token: String?
    var domain: String?
    var proxyUrl = "ws://localhost:8080"

    var i = 1
    while i < args.count {
        switch args[i] {
        case "--token", "--domain", "--proxy":
            let flag = args[i]
            i += 1
            guard i < args.count else {
                fputs("\(flag) requires a value\n", stderr)
                return 1
            }
            switch flag {
            case "--token": token = args[i]
            case "--domain": domain = args[i]
            case "--proxy": proxyUrl = args[i]
            default: break
            }
        default:
            fputs("Unknown argument: \(args[i])\n", stderr)
            return 1
        }
        i += 1
    }

    guard let token = token, let domain = domain else {
        fputs("Both --token and --domain are required\n", stderr)
        return 1
    }

    do {
        let client = try RemoteAccessClient(
            proxyUrl: proxyUrl,
            identityStorage: MemoryIdentityStorage(),
            connectionStorage: MemoryConnectionStorage(),
            eventHandler: nil
        )

        try client.connect()

        if looksLikePskToken(token: token) {
            try client.pairWithPsk(pskToken: token)
        } else {
            let fp = try client.pairWithHandshake(code: token)
            fputs("Handshake fingerprint: \(fp)\n", stderr)
        }

        let cred = try client.requestCredential(domain: domain)
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

exit(main())
