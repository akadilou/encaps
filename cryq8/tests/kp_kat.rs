#[test]
fn kp_kat_deterministic_json_equal() {
    let msg=b"kat codex".to_vec();
    let recip_priv=[7u8;32];
    let recip_sec=x25519_dalek::StaticSecret::from(recip_priv);
    let recip_pub=x25519_dalek::PublicKey::from(&recip_sec);
    let recip_pub32: &[u8;32]=recip_pub.as_bytes();
    let eph_sec=[5u8;32];
    let nonce=[2u8;12];
    let msg_id=[3u8;16];
    let cap1=cryq8::encrypt_keypair_kat_with(eph_sec,recip_pub32,&msg,Some("text/plain"),Some("m.txt"),nonce,msg_id,None).unwrap();
    let cap2=cryq8::encrypt_keypair_kat_with(eph_sec,recip_pub32,&msg,Some("text/plain"),Some("m.txt"),nonce,msg_id,None).unwrap();
    let j1=serde_json::to_string(&cap1).unwrap();
    let j2=serde_json::to_string(&cap2).unwrap();
    assert_eq!(j1,j2);
    let out=cryq8::decrypt_keypair(&recip_priv,&cap1,None).unwrap();
    assert_eq!(out,msg);
}
