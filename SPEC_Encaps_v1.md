Encaps v1 – Spécification minimale auditable

1. Objet
Encapsule un contenu binaire en JSON avec AEAD, AAD canonique, et versionnage. Deux modes: password et codex. Déchiffrement offline, zéro escrow.

2. Encodages et notations
- base64url: RFC 4648, sans padding.
- ts: timestamp Unix (i64, secondes UTC).
- nonce: 12 octets aléatoires.
- msg_id: 16 octets aléatoires.
- Tous les champs binaires sont encodés en base64url.
- Le JSON ne garantit pas l’ordre des clés; l’AAD est une chaîne canonique (voir 6).

3. Algorithmes et paramètres
- AEAD: ChaCha20-Poly1305, clé 32, nonce 12, tag 16.
- KDF (mode password): Argon2id, t=3, m=65536 KiB, p=1, sortie 32 octets, sel 16 octets.
- Codex (mode clé publique): X25519 pour secret partagé. Dérivation session:
  K0 = SHA256("encaps/v1|kp|" || x25519_shared)
  K  = SHA256(K0 || nonce)
- Signature optionnelle expéditeur: Ed25519, sur le JSON codex sans le champ sig_b64.
- CSPRNG: système (OsRng), pour sel, nonce, msg_id, éphémères.

4. Framing et padding
- Message chiffré = frame(len32be || plaintext || padding≤4096 octets aléatoires).
- But: réduction d’information sur la taille.
- KATs utilisent un framing déterministe (len32be || plaintext) pour reproductibilité.

5. Format JSON commun
Champs communs aux deux modes:
- v: u8 (1)
- mode: "password" | "codex"
- nonce_b64: base64url(12)
- meta: { ts: i64, mime?: string, filename?: string }
- msg_id_b64: base64url(16)
- ct_b64: base64url

Mode password ajoute:
- kdf: { alg:"argon2id", t:3, m:65536, p:1, salt_b64: base64url(16) }

Mode codex ajoute:
- ephem_pub_b64: base64url(32) X25519
- recipient_key_id: hex8 = hex(sha256(recipient_pub)[0..4])
- sender_ed25519_pub_b64?: base64url(32)
- sig_b64?: base64url(64)

Exemples:
mode=password
{
  "v":1,"mode":"password","nonce_b64":"...","kdf":{"alg":"argon2id","t":3,"m":65536,"p":1,"salt_b64":"..."},
  "meta":{"ts":..., "mime":"..","filename":".."},
  "msg_id_b64":"...","ct_b64":"..."
}
mode=codex
{
  "v":1,"mode":"codex","nonce_b64":"...",
  "meta":{"ts":..., "mime":"..","filename":".."},
  "msg_id_b64":"...","ephem_pub_b64":"...","recipient_key_id":"...",
  "sender_ed25519_pub_b64":"...","sig_b64":"...","ct_b64":"..."
}

6. AAD canonique
Chaînes ASCII construites ainsi:
- password:
  "v={v}|mode=password|ts={ts}|mime={mime}|filename={filename}|nonce={nonce_b64}|msgid={msg_id_b64}"
- codex:
  "v={v}|mode=codex|ephem={ephem_pub_b64}|kid={recipient_key_id}|ts={ts}|mime={mime}|filename={filename}|nonce={nonce_b64}|msgid={msg_id_b64}"

7. Procédure mode password
Chiffrement:
1) Générer salt(16), nonce(12), msg_id(16).
2) K = Argon2id(password, salt, t=3, m=65536, p=1) → 32.
3) AAD = chaîne password ci-dessus.
4) Framer plaintext.
5) ChaCha20-Poly1305.enc(K, nonce, AAD) → ct.
JSON résultant: champs communs + kdf.
Déchiffrement:
1) Recalculer K avec kdf.
2) Recréer AAD.
3) AEAD.dec(K, nonce, AAD, ct) → frame → plaintext.

8. Procédure mode codex
Chiffrement:
1) X25519: générer eph_sec(32), eph_pub = X25519(eph_sec).
2) shared = DH(eph_sec, recipient_pub).
3) Dérivation: K0=SHA256("encaps/v1|kp|"||shared), K=SHA256(K0||nonce).
4) AAD = chaîne codex ci-dessus (ephem_pub_b64, kid, etc.).
5) Framer plaintext.
6) AEAD.enc(K, nonce, AAD) → ct.
7) Option: signature Ed25519 du JSON sans sig_b64, ajouter sig_b64 et sender_ed25519_pub_b64.
JSON résultant: champs communs + ephem_pub_b64 + recipient_key_id + (option sig).
Déchiffrement:
1) shared = DH(recipient_priv, ephem_pub).
2) Dérivation identique.
3) AAD identique.
4) AEAD.dec(K, nonce, AAD, ct) → frame → plaintext.
5) Si sig présente: vérifier Ed25519(payload=JSON sans sig_b64).

9. Règles de rejet
- AUTH_FAIL si: AAD non concordant, nonce longueur≠12, sel≠16, ephem_pub≠32, signature invalide, tag AEAD invalide, JSON incomplet ou incohérent.
- Interdiction de tolérer des variations silencieuses. Toute anomalie → AUTH_FAIL unique.

10. KATs (tests déterministes)
- pwd: encrypt_password_kat_with(password, pt, mime?, filename?, salt(16), nonce(12), msg_id(16)) → capsule JSON identique bit-à-bit; decrypt_password inverse ok.
- codex: encrypt_keypair_kat_with(eph_sec(32), recip_pub(32), pt, mime?, filename?, nonce(12), msg_id(16), sign?) → capsule JSON identique; decrypt_keypair ok.
- Les KATs sont fournis dans cryq8/tests.

11. Sécurité opérationnelle
- Offline complet: aucune dépendance réseau au déchiffrement.
- Zéro escrow: aucune sauvegarde de clés dérivées; effacement mémoire des clés (zeroize).
- PFS: nouveau éphémère X25519 à chaque codex.
- Padding: ≤4096 aléatoire en usage normal (KATs en framing déterministe).
- Aucune télémétrie.

12. Versionnage et compatibilité
- v=1 obligatoire. Toute version inconnue → rejet.
- Paramètres KDF minimums: Argon2id t≥3, m≥65536 KiB, p≥1. Valeurs plus faibles → rejet.
- Suite codex fixée à X25519+ChaCha20-Poly1305; signature Ed25519 optionnelle.

13. Identifiants et vérification humaine
- recipient_key_id: hex8 = hex(sha256(recipient_pub)[0..4]).
- verify_code (Ed25519): hex du SHA-256(pub) tronqué 15 octets, imprimé par groupes de 6 caractères.

14. Erreurs
- AUTH_FAIL: unique pour toutes erreurs d’authentification et de validation, sans oracle d’information.
- Autres erreurs: entrées invalides, JSON non parsable → messages génériques.

15. Conformité
- Implémentation de référence: cryq8 (Rust).
- CLI de référence: cryq8_cli.
- CI: build, tests, audit dependencies.
- KATs: fournis dans le repo pour reproductibilité.

16. Menaces non couvertes
- Compromission totale du terminal au moment de l’affichage.
- Attaques visuelles hors écran (photo).
- Fuites via canaux annexes hors du périmètre applicatif.

