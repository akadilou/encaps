# Encaps (core + CLI)
## Build
cargo build --release -p cryq8 && cargo build --release -p cryq8_cli
## Test
cargo test -p cryq8
## Usage CLI
./target/release/cryq8_cli encpwd --password "Fort!2025" --inp doc.pdf --out doc.pdf.q8msg --mime application/pdf --filename doc.pdf
./target/release/cryq8_cli decpwd --password "Fort!2025" --inp doc.pdf.q8msg --out doc_restored.pdf

---

## 🔒 Security Engineering

- ✅ 100% Safe Rust, no `unsafe` blocks.
- ✅ Dependencies continuously tracked with **cargo-deny** & **cargo-audit**.
- ✅ SPEC v1 is **minimal and frozen**, ensuring external auditability.
- ✅ Designed for external security audits (independent verification encouraged).

---

## 🧾 Audit & Trust

Encaps v1.0.0 is published with:

- 📄 **SBOM (CycloneDX)** for supply chain transparency.
- 🔑 **SHA256SUMS.txt** for binary verification.
- 🛡️ Clear threat model: *resistant to most adversaries; against Pegasus-class spyware, exposure window is minimized*.
