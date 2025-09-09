# Encaps ![CI](https://github.com/akadilou/encaps/actions/workflows/ci.yml/badge.svg) 
![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)

**Military-grade end-to-end encryption core (Rust, CLI, FFI) powering secure messaging and file 
capsules.**

---

## ✨ Features
- 🔐 Password-based encryption (Argon2id + ChaCha20Poly1305)
- 🔑 Keypair-based encryption (X25519 + Ed25519 signing)
- 📦 Encapsulation of files with metadata (MIME, filename)
- 🚫 Anti-replay protections (KATs, deterministic vectors)
- 🛠 CLI & FFI bindings (macOS/Linux/Windows)
- ✅ CI pipeline (build, test, audit, SBOM)
- 📱 QR split/join for offline transmission on paper/photos

---

## 🚀 Build

```sh
git clone https://github.com/akadilou/encaps.git
cd encaps
cargo build --release -p cryq8
cargo build --release -p cryq8_cli
cargo build --release -p cryq8_ffi


⸻

🧪 Test

cargo test -p cryq8


⸻

🔧 Usage CLI (basique)

Chiffrement / déchiffrement simple avec mot de passe :

./target/release/cryq8_cli encpwd \
  --password "Fort!2025" \
  --inp doc.pdf \
  --out doc.pdf.q8msg \
  --mime application/pdf \
  --filename doc.pdf

./target/release/cryq8_cli decpwd \
  --password "Fort!2025" \
  --inp doc.pdf.q8msg \
  --out doc_restored.pdf


⸻

📖 Exemple complet avec QR codes

# 1. Créer un message
echo "Secret militaire" > secret.txt

# 2. Chiffrer avec mot de passe
./target/release/cryq8_cli encpwd \
  --password "Fort!2026" \
  --inp secret.txt \
  --out secret.q8msg \
  --mime text/plain \
  --filename secret.txt

# 3. Découper en QR codes (lisibles sur papier ou photo)
./target/release/cryq8_cli qr-split \
  --inp secret.q8msg \
  --out-dir qrs \
  --chunk 900 \
  --ecc M

# Résultat : qrs/xxxxx_001.png ... qrs/xxxxx_007.png

# 4. Le destinataire scanne les QR, puis les rejoint
./target/release/cryq8_cli qr-join \
  --dir qrs \
  --out joined.q8msg

# 5. Il déchiffre avec le mot de passe partagé
./target/release/cryq8_cli decpwd \
  --password "Fort!2026" \
  --inp joined.q8msg \
  --out restored.txt

# Vérification
diff secret.txt restored.txt && echo OK

📌 Pipeline visuel :

plaintext → encpwd → fichier .q8msg → qr-split → QR codes (papier/photo)
       → qr-join → fichier .q8msg → decpwd → plaintext


⸻

🔒 Security Engineering
	•	✅ 100% Safe Rust, no unsafe blocks.
	•	✅ Dependencies continuously tracked with cargo-deny & cargo-audit.
	•	✅ SPEC v1 is minimal and frozen, ensuring external auditability.
	•	✅ Designed for external security audits (independent verification encouraged).

⸻

🧾 Audit & Trust

Encaps v1.0.0 is published with:
	•	📄 SBOM (CycloneDX) for supply chain transparency.
	•	🔑 SHA256SUMS.txt for binary verification.
	•	🛡️ Clear threat model: resistant to most adversaries; against Pegasus-class 
spyware, exposure window is minimized.

⸻

📬 Security Contact

For vulnerabilities or security issues, please follow the policy in SECURITY.md.

