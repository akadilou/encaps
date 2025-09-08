# 🔐 Security Policy

## 📌 Supported Versions
We support only the latest tagged release (currently **v1.0.0**).  
Older versions are considered insecure and are not maintained.  

---

## 📣 Reporting a Vulnerability
If you discover a vulnerability, **do not open a public issue**.  
Instead, report it responsibly to:  

📧 **security@encaps.dev**  
🔑 Public PGP key: [`encaps-security-pubkey.asc`](./encaps-security-pubkey.asc)  

- We aim to respond within **72h**.  
- Patches will be issued within **14 days**, depending on severity.  

---

## 🔏 Disclosure Policy
- **Coordinated disclosure** is required: researchers must allow us to validate and patch before 
public release.  
- Critical vulnerabilities → **security advisory** published here + CVE registration.  
- All patches increment the **minor version** (e.g. `v1.0.1`).  

---

## 🛡️ Security Principles
- Safe Rust only (`#![forbid(unsafe_code)]`).  
- Memory-hard KDF: **Argon2id** (`t=3, m=64MiB, p=1`) → 32B key; zeroized after use.  
- AEAD: **ChaCha20-Poly1305 (256-bit)**, nonce 12B from CSPRNG.  
- AAD (associated data) = `v|mode|ts|mime|filename|nonce|msgid`; any mutation ⇒ AUTH_FAIL.  
- Framing + random padding (≤4KiB) to blur size.  
- Filenames sanitized; no plaintext leaks outside explicit output path.  
- Tests include roundtrip + tamper; fuzzing recommended before releases.  
- Versioned format (`v=1`); future upgrades MUST reject unknown/weak params.  

---

## 🔑 PGP Key for Secure Reports
- **Fingerprint:** `7C120867DE7EC797D23517C40691BB5B8505FC19`  
- **Public key file:** [`encaps-security-pubkey.asc`](./encaps-security-pubkey.asc)  
