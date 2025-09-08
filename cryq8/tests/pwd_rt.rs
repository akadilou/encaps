#[test]
fn pwd_roundtrip() {
    let pt=b"secret pwd".to_vec();
    let cap=cryq8::encrypt_password("S3cure!",&pt,Some("text/plain"),Some("a.txt")).unwrap();
    let out=cryq8::decrypt_password("S3cure!",&cap).unwrap();
    assert_eq!(pt,out);
}
