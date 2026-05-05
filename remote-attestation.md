# RemoteClient Identity Attestation

An optional extension to the Agent Access Protocol that lets a UserClient
apply policy on which RemoteClients it accepts, based on signed claims
issued by the operator of the RemoteClient (typically the SaaS platform the RemoteClient
runs on).

Status: draft.

Authors:
* Anders Åberg, Bitwarden <aaberg@bitwarden.com>

## 1. Introduction

### 1.1 Motivation

In v0 the RemoteClient identity is anonymous. It is a raw signing key
that the UserClient learns about during pairing.

Several deployment scenarios benefit from richer policy:

- "Only accept agents running on the platform example.com."
- "Only accept agents in the ACME INC project on example.com."
- "Only accept agents on servers ACME INC has provisioned."

This document specifies a binding token format and a verification
procedure that lets a UserClient enforce such policy without operating
its own identity infrastructure. The trust anchor is a public key the
vendor publishes at an HTTPS URL named in the token; or, configured
manually if web PKI is unsuitable.

### 1.2 Scope and non-goals

In scope:

- Wire format of a vendor-signed binding token (CWT / COSE_Sign1).
- Algorithms, headers, claims, and binding to a specific Noise session.
- Verification procedure performed by the UserClient.

Out of scope:

- Proxy-side enforcement. The proxy is treated as an untrusted relay,
  consistent with v0's threat model. The proxy does not parse, verify,
  or attach attestation data.
- Replacement of pairing. The binding token is an
  additional layer of authentication, not a substitute for pairing.

### 1.3 Relation to v0

This extension does not change the proxy protocol, the Noise handshake,
or the transport layer. It adds:

1. One new application-layer message (§5.1).

A UserClient that does not enable this extension behaves exactly as in
v0. A UserClient that enables it MAY require a valid token for some or
all connections, per its own configuration. When a token is required
and verification fails, the connection MUST be rejected (§6.5).

## 2. Overview

```
   ┌────────────┐  (1) signs token (sub,              ┌──────────────┐
   │   Vendor   │      session binding)           ───►│ RemoteClient │
   │            │                                     └──────┬───────┘
   └────────────┘                                            │ (2) presents token
          ▲                                          ┌───────▼──────┐
          └──────── (3) fetch JWKS ──────────────────│  UserClient  │
                                                     │  (verifies)  │
                                                     └──────────────┘
```

1. Vendor publishes its public verification key set at an HTTPS URL
   on its own origin. Web PKI authenticates the vendor's domain.
2. Vendor signs a token attesting to facts about the RemoteClient
   (identity public-key thumbprint, tenant identifiers, workload
   identifiers, etc.) and binds the signature to a specific Noise
   session via `external_aad`.
3. RemoteClient presents the vendor-signed token to the UserClient as
   the first message after the Noise handshake completes (§5). How
   the vendor's signing key is held (locally, in an HSM, or behind a
   remote signing service) is an implementation choice.
4. UserClient verifies signature, claims, and binding against its
   configured policy. If verification fails, the connection is
   rejected; there is no fallback (§6.5).

## 3. Trust model

A successful verification (§6) produces an **authenticated identity**:
a verified `(iss, claims)` tuple bound to a specific Noise session.
What the UserClient does with that identity (accept the connection
unconditionally or apply policy gates) is an implementation choice and is not
specified here.

The default behaviour the spec enables is "give the UserClient a
trustworthy identity for the peer." Policy evaluation is layered on
top.

The verification anchor is web PKI. The token names its JWKS URL via
the `jku` header parameter (§4.3); the UserClient fetches that URL over TLS,
which authenticates the issuer's domain. The `jku` URL MUST be on
the same origin as `iss`, so the host the verifier reaches is the
host policy is applied to. A UserClient operating in environments
where web PKI is unfeasible MUST instead configure the issuer's
verification key out-of-band; that mode is otherwise identical.

UserClients MAY:

- Auto-discover previously unseen issuers by fetching the JWKS named
  by the token.
- Maintain a pre-configured allowlist of issuers or claims.
- Surface a first-contact prompt that pins the `(iss, key)` binding
  for subsequent connections (trust-on-first-use).
- Combine any of the above.

This extension does not modify the proxy's threat model. The proxy
remains an untrusted relay. The binding token is verified end-to-end
at the UserClient.

## 4. Token format

The token is a CWT (RFC 8392), serialized as COSE_Sign1 (RFC 9052).

Header and claim fields are referenced in this document by their
JOSE/IANA registered names (e.g., `iss`, `kid`, `typ`). The CWT
integer label for each appears alongside in §4.3 and §4.4.

Public verification keys are published as JWKS (RFC 7517); see §4.2.
Verifiers convert each JWK to a `COSE_Key` (RFC 9052 §7) at
verification time.

### 4.1 Algorithms

A verifier MUST accept exactly the following signature algorithms and
MUST reject any other:

| Name      | COSE alg | JOSE alg | Notes                            |
|-----------|----------|----------|----------------------------------|
| EdDSA     | -8       | `EdDSA`  | Ed25519, RFC 8037                |
| ML-DSA-65 | -49      | `ML-DSA-65` | FIPS 204; COSE registration per draft-ietf-cose-dilithium |

The set is intentionally narrow. Adding an algorithm requires a spec
revision. RSA, ECDSA, HMAC, and `none` are explicitly forbidden;
verifiers MUST reject them at the parser level, not by allowlist.

### 4.2 JWKS publication (issuer requirements)

The issuer MUST publish a JWKS (RFC 7517) at an HTTPS URL on the
same origin as `iss`. The token names this URL via the `jku` header
parameter (§4.3). Verifiers convert each JWK to a `COSE_Key` (RFC 9052 §7) at
verification time, using the standard JOSE-to-COSE parameter mapping.

Each JWK in the document MUST:

- Have a unique `kid`. Verifiers MUST reject the entire JWKS if any
  `kid` is duplicated.
- Have an `alg` matching one of the algorithms in §4.1 exactly.
- Have `key_ops` equal to `["verify"]`. JWKs with any other
  `key_ops` value MUST be ignored by verifiers.
- Contain only public-key parameters. Verifiers MUST reject any JWK
  that contains private-key parameters (e.g., `d` for OKP keys).

For each algorithm in §4.1, the JWK parameters are pinned:

| Algorithm | `kty` | Curve / extra params | Public key parameter | Reference |
|-----------|-------|----------------------|----------------------|-----------|
| EdDSA     | `OKP` | `crv: Ed25519`       | `x` (32-byte, base64url) | RFC 8037 |
| ML-DSA-65 | per draft-ietf-jose-pqc | per draft-ietf-jose-pqc | per draft-ietf-jose-pqc | draft-ietf-jose-pqc |

Verifiers MUST reject a JWK whose `kty` (and `crv`, where applicable)
does not match the value pinned for the JWK's `alg`.

The JWKS document SHOULD set HTTP cache headers reflecting its
rotation policy. Verifiers honor `Cache-Control` (§6.4).

### 4.3 Header

The COSE protected header contains exactly the following parameters:

| Parameter | COSE label | Required | Value                                                        |
|-----------|------------|----------|--------------------------------------------------------------|
| `typ`     | 16         | yes      | `x.agentaccess-binding+cwt`                                  |
| `kid`     | 4          | yes      | A `kid` present in the issuer's JWKS                         |
| `jku`     | 32         | yes      | HTTPS URL of the JWKS document; hostname MUST equal `iss`    |

The `jku` URL MUST satisfy:

- Scheme is `https`.
- Hostname (case-insensitive) equals `iss`.
- No userinfo, fragment, or query component.

The header MUST NOT contain:

- `alg` (label 1). The signature algorithm is determined by the JWK
  referenced by `kid`. A token whose protected header carries `alg`
  MUST be rejected, even if its value matches the JWK's algorithm.
- Any parameter that embeds or names a key directly (e.g., COSE
  `kid`-equivalents in the unprotected header, embedded keys). Only
  `kid` in the protected header is permitted for key reference.
- Duplicate map keys. The encoded protected header MUST contain each
  label at most once. Verifiers MUST reject on duplicates.

The protected header MUST be encoded with deterministic CBOR encoding
(RFC 8949 §4.2.1), so the byte representation that the signature
covers is canonical. The unprotected header MUST be empty.

The `typ` value will be changed to
`application/vnd.agentaccess-binding+cwt` once registered with IANA;
until then `x.` is used per RFC 6838 §3.4.

### 4.4 Claims

| Claim          | CWT key | Required | Value                                                |
|----------------|---------|----------|------------------------------------------------------|
| `iss`          | 1       | yes      | Hostname only (e.g., `token.browserbase.com`)        |
| `sub`          | 2       | yes      | Hex-encoded `IdentityFingerprint` of the RemoteClient |
| `exp`          | 4       | no       | Unix seconds; default `iat + MAX_LIFETIME`           |
| `iat`          | 6       | yes      | Unix seconds                                         |

The Noise session binding (§4.5) is not a claim in the payload; it
is carried as COSE `external_aad`.

Additional claims MAY appear with the prefix `x.`. Verifiers MUST
ignore unknown claims that begin with `x.`. Unknown claims that do not
begin with `x.` MUST cause rejection.

The encoded payload MUST NOT contain duplicate keys. Verifiers MUST
reject on duplicates.

#### 4.4.1 `iss`

The issuer's hostname (no scheme, no path, no port). Used by the
UserClient as the policy identifier and as the same-origin check
against `jku`. Tokens whose `iss` includes anything other than a
hostname MUST be rejected.

#### 4.4.2 `sub`

Hex-encoded `IdentityFingerprint` (§2 of `protocol-v0.md`):
`hex(SHA256(public_key_bytes))`, 64 characters. The verifier MUST
confirm this equals the `IdentityFingerprint` of the public key the
peer authenticated to the proxy with.

#### 4.4.3 `iat` and `exp`

Both are Unix seconds (integer). The verifier evaluates against its
local wall clock `now`:

```
SKEW         = 60          // seconds
MAX_LIFETIME = 300         // seconds

verifier MUST reject unless:
  iat is present AND iat ∈ [now - SKEW, now + SKEW]
  exp ∈ (now, now + MAX_LIFETIME]   (default exp = iat + MAX_LIFETIME)
  exp - iat ≤ MAX_LIFETIME
```

The maximum effective validity from any clock is therefore
`MAX_LIFETIME + 2·SKEW = 7 minutes`. This bound is intentional. Issuers
MUST NOT set `exp` greater than `iat + MAX_LIFETIME`; verifiers MUST
reject if they do.

### 4.5 Binding to the Noise session

The token's signature MUST cover the binding value of the Noise
session it authenticates. This binds the token to a single session,
eliminating bearer-token replay even within the validity window.

The binding value is the 32-byte SHA256 of the concatenated transport
split keys derived during the Noise handshake (`protocol-v0.md` §4.3):

```
binding = SHA256(r2i_key || i2r_key)    // 32 bytes
```

Both peers can compute it locally from `MultiDeviceTransport` after
the Noise handshake finalizes, with no additional state from the
underlying Noise library.

The binding is the COSE `external_aad`, used as raw bytes. The
verifier supplies the same value when verifying COSE_Sign1, so the
signature fails if the token is presented in a different session.

## 5. Wire format

The binding token rides in a new application-layer message, sent
(when present) as the first transport-phase message after the Noise
handshake completes. Presence is OPTIONAL; UserClient handling is
described in §5.1.

### 5.1 `BindingAttestation` message

A new variant on the v0 `ProtocolMessage` enum:

```
ProtocolMessage::BindingAttestation {
  token:   bytes,  // COSE_Sign1 (RFC 9052) bytes
}
```

Sent inside the Noise transport (encrypted, AEAD-authenticated). The
proxy sees only opaque bytes.

A UserClient that does not require a token MAY accept and verify
`BindingAttestation` if present, or ignore it; in either case the
absence of the message is not a protocol violation.


A UserClient that requires a token for the connection MUST:

- Treat absence of `BindingAttestation` as the first message as a
  protocol violation, and reject the connection (§6.5).
- Ignore any other application-layer message arriving before
  `BindingAttestation`.
- Verify the token per §6 before sending or accepting any further
  application-layer message.

On verification success, no acknowledgement is sent; the UserClient
proceeds with the normal credential-request flow. On verification
failure when a token is required, the UserClient MUST close the
Noise session and the underlying proxy connection.


## 6. Verification procedure

The UserClient performs the following steps in order. Any failure at
any step results in immediate rejection, closure of the Noise session,
and closure of the underlying proxy connection. There is no fallback
(§6.5).

### 6.1 Parse

1. Decode the `BindingAttestation` message.
2. Parse as COSE_Sign1 (RFC 9052) with deterministic-CBOR enforcement
   (RFC 8949 §4.2.1). Reject on duplicate map keys, indefinite-length
   items, or non-canonical encodings.
3. Reject if the unprotected header is non-empty.

### 6.2 Validate header

1. `typ` (label 16) equals the expected value (§4.3).
2. `kid` (label 4) is present in the protected header.
3. `jku` (label 32) is present and satisfies the URL constraints (§4.3).
4. `alg` (label 1) is absent from the protected header.
5. No unrecognized labels are present in the protected header.

### 6.3 Validate claims

1. `iss` is a syntactically valid hostname (no scheme, path, or
   port) and its value equals the hostname of `jku` (§4.3). Whether
   `iss` is pre-trusted, auto-discovered, or surfaced for
   first-contact approval is an implementation choice (§3, §7).
2. `sub` equals `hex(SHA256(remote_client_pubkey))` of the peer that
   completed the Noise handshake.
3. `iat` is within `[now - SKEW, now + SKEW]`.
4. `exp`, if present, satisfies `exp ∈ (now, now + MAX_LIFETIME]` and
   `exp - iat ≤ MAX_LIFETIME`. If absent, treat as `iat + MAX_LIFETIME`
   and apply the same bound.

Steps 1–4 produce an authenticated identity. Whether that identity
is acceptable for the connection (claim policy, issuer allowlisting,
TOFU prompts, etc.) is evaluated separately by the UserClient per §3.

### 6.4 Fetch / verify signature

1. Look up `kid` in the cached JWKS for the `jku` URL (§4.3).
2. If absent, fetch that URL once. If the fetch fails
   or the JWKS is malformed (including duplicate `kid`), reject. If
   `kid` is still absent after a successful fetch, reject.
3. Confirm the JWK's `key_ops` is exactly `[verify]` and its `alg` is
   in §4.1.
4. Convert the JWK to a `COSE_Key` (RFC 9052 §7).
5. Verify the COSE_Sign1 signature, supplying the locally computed
   session binding (§4.5) as `external_aad`.
6. Cache: respect HTTP `Cache-Control: max-age` from the JWKS
   response. Force-refresh on unknown `kid` no more than once per
   minute per issuer.

### 6.5 Verification failure

When a UserClient's configuration requires a binding token for a
connection and any step in §6.1–§6.4 fails, the UserClient MUST
reject the connection. It MUST NOT accept the connection on weaker
grounds, e.g., by promoting the peer to a non-attested authentication
path that the configuration would not otherwise permit.

A UserClient MAY operate in mixed mode, requiring tokens for some
peers and not others, per configuration.

## 7. Configuration (non-normative)

The shape of UserClient trust configuration is an implementation
concern and not specified here. The following YAML is illustrative
only, intended to make the verification procedure (§6) concrete:

```yaml
attestation:
  trusted_issuers:
    - hostname: token.browserbase.com
      require:
        project_id: acme-inc
```

Implementations are free to express the same policy in any form
(config file, API, UI, code).

## 8. Security considerations

### 8.1 Why no fallback

If a UserClient that requires a token treats verification failure as
a soft signal (prompting the user, accepting on weaker grounds, etc.),
an attacker who can suppress or corrupt the token can downgrade the
connection to a verification path that the policy would not otherwise
admit. Strict rejection on failure is the only mode that preserves
the policy guarantee. UserClients MAY of course choose not to require
a token for a given connection in the first place; the rule only
applies once a token is required.

### 8.2 Trust in web PKI

This extension trusts web PKI to authenticate the issuer's domain.
This is appropriate for the SaaS-vendor scenario but inappropriate for
deployments where web PKI is in scope of the threat model. Such
deployments MUST configure issuer keys out-of-band.

### 8.3 Issuer key compromise

A compromise of the issuer's signing key allows the attacker to spoof their
identity, claiming to be the issuer. However it does not impact encryption
of the noise tunnel or existing connections. Only new pairings.

- Issuers SHOULD rotate signing keys at some interval and MUST publish only
  current keys in the JWKS. Removing a `kid` from the JWKS effectively
  revokes any token signed by it once verifier caches expire.

### 8.4 Replay and audience binding

The token's signature covers the Noise session binding (§4.5), so a
captured token only verifies against the specific session that
produced it. New handshakes derive new split keys, hence a new
binding value, hence a different signature input. 

For the same reason, an explicit `aud` claim binding the token to a
specific UserClient is unnecessary. A Noise session is established
between exactly one RemoteClient and one UserClient; the session
binding already ties the token to that pair. A token cannot be
redirected to a different UserClient without a new handshake, which
produces a new binding that the original token's signature does not
cover.

### 8.5 Clock skew

The 60-second skew tolerance is a balance between accommodating
real-world clocks and bounding the replay window. Devices with
unreliable clocks (no NTP, no battery-backed RTC) may need a larger
skew, but this comes at the cost of a larger acceptance window.
Implementations SHOULD log clock skew between issuer and verifier so
operators can detect drift.

### 8.6 Forbidden algorithms

`alg=none`, HMAC-based algorithms, and RSA-based algorithms are
forbidden. Verifiers MUST reject these at the parser level, not by
algorithm-allowlist comparison after parsing, because a parser that
accepts `alg=none` may not preserve the algorithm identifier through
to the allowlist check.

### 8.7 `alg` not in header

Pinning the algorithm via the JWK `alg` (selected by `kid`) and
forbidding `alg` in the token header eliminates the family of
algorithm-confusion attacks where an attacker chooses an algorithm
that the verifier accepts but the issuer did not intend. The cost is
that issuers cannot signal the intended algorithm in the token; this
is acceptable because the JWKS already carries it.

## 9. Open items

- IANA registration of the `typ` value, replacing the `x.` prefix
  with `application/vnd.agentaccess-binding+cwt`.
- ML-DSA COSE algorithm identifier is currently per
  `draft-ietf-cose-dilithium`; this spec should pin the final IANA
  assignment when published.
- Claims schema: We may want to define or lean on an existing schema for claim keys (`x.project_id` etc), and for oattern matching for `require` claims (regex, glob, set membership).
- Certificate / Hierarchical issuer trust (issuer A vouches for issuer B). v0 of
  this extension is flat.
- Evaluate alignment with EAT (Entity Attestation Token,
  draft-ietf-rats-eat): its `nonce` claim (CWT key 10) covers a
  similar freshness/binding role, and its extension mechanism could
  anchor the `x.` claim vocabulary.

## 10. References

- RFC 7517 — JSON Web Key (JWK)
- RFC 8037 — CFRG ECDH and Signatures in JOSE (EdDSA)
- RFC 8392 — CBOR Web Token (CWT)
- RFC 8610 — Concise Data Definition Language (CDDL)
- RFC 8949 — Concise Binary Object Representation (CBOR)
- RFC 9052 — CBOR Object Signing and Encryption (COSE)
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- draft-ietf-jose-pqc — JOSE post-quantum signature algorithms (informative)
- `protocol-v0.md` — Agent Access Protocol v0
