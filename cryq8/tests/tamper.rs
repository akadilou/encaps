use base64::Engine;

#[test]
fn tamper_fails() {
    let pt = b"secret".to_vec();
    let mut cap = cryq8::encrypt_password("x", &pt, None, None).unwrap();
    let mut ct = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cap.ct_b64.as_bytes())
        .unwrap();
    ct[0] ^= 1;
    cap.ct_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ct);
    assert!(cryq8::decrypt_password("x", &cap).is_err());
}
