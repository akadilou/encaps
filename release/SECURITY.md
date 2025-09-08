# Security Policy (Encaps v1)
- No escrow. No server. Offline decryption MUST work.
- AEAD: ChaCha20-Poly1305 (256-bit), nonce 12B from CSPRNG.
- KDF: Argon2id (t=3, m=64MiB, p=1) -> 32B key; zeroize after use.
- AAD canonical: v|mode|ts|mime|filename|nonce|msgid; any mutation => AUTH_FAIL.
- Framing + random padding (<=4KiB) to blur size.
- Metadata sanitize (filename). Never write plaintext outside explicit paths.
- Tests: roundtrip + tamper. Fuzzing recommended before release.
- Versioned format (v=1). Future upgrades MUST refuse unknown/weak params.
