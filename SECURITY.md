# Security Policy

## Supported Versions
We support only the latest tagged release (currently 
**v1.0.0**).
Older versions should be considered insecure and are not 
maintained. 

## Reporting a Vulnerability
If you discover a vulnerability, please **do not open a 
public issue**.
Instead, report it responsibly to:
📧 security@encaps.dev (PGP key available on request)

We aim to respond within **72h** and issue a patch within 
**14 days** depending on severity.

## Disclosure Policy
- **Coordinated disclosure** is expected: researchers must 
allow us to validate and patch before public release.
- Critical vulnerabilities will result in a **security 
advisory** published in the repo and CVE registration.
- All patches will bump the **minor version** (e.g., 
`v1.0.1`).

## Security Principles
- 🛡️ Safe Rust only (`#![forbid(unsafe_code)]`)
- 🔑 Memory-hard KDF (Argon2id)
- 📦 Auditable SBOM (CycloneDX)
- ✅ Continuous dependency scanning (`cargo-deny`, 
`cargo-audit`)
- 🔒 Anti-replay and deterministic KATs# 
Security Policy (Encaps 
v1)
- No escrow. No server. Offline decryption MUST work.
- AEAD: ChaCha20-Poly1305 (256-bit), nonce 12B from CSPRNG.
- KDF: Argon2id (t=3, m=64MiB, p=1) -> 32B key; zeroize after use.
- AAD canonical: v|mode|ts|mime|filename|nonce|msgid; any mutation => AUTH_FAIL.
- Framing + random padding (<=4KiB) to blur size.
- Metadata sanitize (filename). Never write plaintext outside explicit paths.
- Tests: roundtrip + tamper. Fuzzing recommended before release.
- Versioned format (v=1). Future upgrades MUST refuse unknown/weak params.
## 🔑 PGP Key for Secure Reports                           

For encrypted vulnerability disclosure, use our public key:

- Fingerprint: `7C120867DE7EC797D23517C40691BB5B8505FC19`
- Public key: [`SECURITY_PUBKEY.asc`](./SECURITY_PUBKEY.asc)
