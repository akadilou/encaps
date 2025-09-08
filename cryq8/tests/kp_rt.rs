#[test]
fn kp_roundtrip() {
    let msg = b"secret codex".to_vec();

    let recip_priv = [7u8; 32];
    let recip_sec = x25519_dalek::StaticSecret::from(recip_priv);
    let recip_pub = x25519_dalek::PublicKey::from(&recip_sec);
    let recip_pub32: &[u8; 32] = recip_pub.as_bytes();

    let sender_priv = [5u8; 32];

    let cap = cryq8::encrypt_keypair(
        &sender_priv,
        recip_pub32,
        &msg,
        Some("text/plain"),
        Some("m.txt"),
        None
    ).unwrap();

    let out = cryq8::decrypt_keypair(&recip_priv, &cap, None).unwrap();
    assert_eq!(msg, out);
}
