# Encaps v1.0.0 — Core + CLI + FFI

**Military-grade end-to-end encryption core (Rust, CLI, FFI) powering secure messaging and file capsules.**

## Features
- Password-based encryption (Argon2id + ChaCha20-Poly1305)
- Keypair-based encryption (X25519 + Ed25519 signatures)
- Metadata encapsulation (MIME, filename, ts, msg_id)
- Anti-replay protections (KATs, deterministic vectors)
- CLI: encpwd/decpwd, enckp/deckp, keygen-x/keygen-ed
- FFI: libcryq8_ffi for mobile/desktop bindings
- CI: build, test, audit, SBOM

## Security
- Safe Rust only (`#![forbid(unsafe_code)]`)
- Zero plaintext persistence by design
- AAD canonicalization; any mutation => AUTH_FAIL
- SBOM (CycloneDX) + SHA256SUMS
- Security Policy + PGP public key published

## Artifacts
- encaps_v1_macos_cli.tgz
- release/ffi_macos: libcryq8_ffi.dylib, header, checksums

## Disclosure
- Supported: latest release only (v1.0.0)
- Reporting: see SECURITY.md
- PGP fingerprint: 7C120867DE7EC797D23517C40691BB5B8505FC19
