#[test]
fn rt() {
    let pt = b"hello world".to_vec();
    let cap = cryq8::encrypt_password("S3cure!", &pt, Some("text/plain"), Some("h.txt")).unwrap();
    let out = cryq8::decrypt_password("S3cure!", &cap).unwrap();
    assert_eq!(pt, out);
}
