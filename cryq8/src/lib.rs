use anyhow::{anyhow,bail,Result};
use argon2::{Algorithm,Argon2,Params,Version};
use base64::Engine;
use rand::{rngs::OsRng,RngCore};
use serde::{Deserialize,Serialize};
use time::OffsetDateTime;
use chacha20poly1305::aead::{Aead,KeyInit,Payload};
use chacha20poly1305::{ChaCha20Poly1305,Nonce};
use zeroize::Zeroize;
use sha2::{Sha256,Digest};
use x25519_dalek::{StaticSecret as X25519Secret,PublicKey as X25519Public};
use ed25519_dalek::{SigningKey,VerifyingKey,Signature,Signer,Verifier};

const V:u8=1;
const MODE_PWD:&str="password";
const MODE_KP:&str="codex";
const ARGON_T:u32=3;
const ARGON_M_KIB:u32=64*1024;
const ARGON_P:u32=1;
const ARGON_OUT:usize=32;
const MAX_PAD:usize=4096;

fn b64e(d:&[u8])->String{base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d)}
fn b64d(s:&str)->Result<Vec<u8>>{Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)}
fn now_ts()->i64{OffsetDateTime::now_utc().unix_timestamp()}
fn sanitize_filename(s:Option<&str>)->Option<String>{s.map(|name|{
  let mut out=String::with_capacity(name.len());
  for ch in name.chars(){let ok=ch.is_ascii_alphanumeric()||matches!(ch,'.'|'-'|'_'|' ');if ok{out.push(ch)}}
  let trimmed=out.trim();if trimmed.is_empty(){"file.bin".to_string()}else{trimmed.to_string()}
})}
fn frame_with_padding(pt:&[u8])->Vec<u8>{
  let mut out=Vec::with_capacity(4+pt.len()+MAX_PAD);
  out.extend_from_slice(&(pt.len() as u32).to_be_bytes());
  out.extend_from_slice(pt);
  let mut pad=vec![0u8;MAX_PAD];
  let mut n=[0u8;2];OsRng.fill_bytes(&mut n);
  let pad_len=(u16::from_be_bytes(n) as usize)%MAX_PAD;
  if pad_len>0{OsRng.fill_bytes(&mut pad[..pad_len]);out.extend_from_slice(&pad[..pad_len]);}
  out
}
fn deframe(mut buf:Vec<u8>)->Result<Vec<u8>>{
  if buf.len()<4{bail!("AUTH_FAIL")}
  let mut lenb=[0u8;4];lenb.copy_from_slice(&buf[..4]);
  let want=u32::from_be_bytes(lenb) as usize;
  if 4+want>buf.len(){bail!("AUTH_FAIL")}
  buf.drain(0..4);
  Ok(buf[..want].to_vec())
}
fn aad_pwd(v:u8,ts:i64,mime:&str,filename:&str,nonce_b64:&str,msg_id_b64:&str)->Vec<u8>{
  format!("v={}|mode={}|ts={}|mime={}|filename={}|nonce={}|msgid={}",v,MODE_PWD,ts,mime,filename,nonce_b64,msg_id_b64).into_bytes()
}
fn aad_kp(v:u8,ephem_b64:&str,kid:&str,ts:i64,mime:&str,filename:&str,nonce_b64:&str,msg_id_b64:&str)->Vec<u8>{
  format!("v={}|mode={}|ephem={}|kid={}|ts={}|mime={}|filename={}|nonce={}|msgid={}",v,MODE_KP,ephem_b64,kid,ts,mime,filename,nonce_b64,msg_id_b64).into_bytes()
}
fn sha256(data:&[u8])->[u8;32]{let mut h=Sha256::new();h.update(data);let o=h.finalize();let mut r=[0u8;32];r.copy_from_slice(&o);r}
fn kid_from_pub(pub32:&[u8])->String{let h=sha256(pub32);hex::encode(&h[..4])}

#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct Capsule{pub v:u8,pub mode:String,pub nonce_b64:String,pub kdf:Option<Kdf>,pub meta:Meta,pub msg_id_b64:String,pub ct_b64:String}
#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct Kdf{pub alg:String,pub t:u32,pub m:u32,pub p:u32,pub salt_b64:String}
#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct Meta{pub ts:i64,#[serde(skip_serializing_if="Option::is_none")]pub mime:Option<String>,#[serde(skip_serializing_if="Option::is_none")]pub filename:Option<String>}
#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct CapsuleKp{
  pub v:u8,
  pub mode:String,
  pub nonce_b64:String,
  pub meta:Meta,
  pub msg_id_b64:String,
  pub ephem_pub_b64:String,
  pub recipient_key_id:String,
  #[serde(skip_serializing_if="Option::is_none")]
  pub sender_ed25519_pub_b64:Option<String>,
  #[serde(skip_serializing_if="Option::is_none")]
  pub sig_b64:Option<String>,
  pub ct_b64:String
}

pub fn encrypt_password(password:&str,plaintext:&[u8],mime:Option<&str>,filename:Option<&str>)->Result<Capsule>{
  let params=Params::new(ARGON_M_KIB,ARGON_T,ARGON_P,Some(ARGON_OUT)).map_err(|e|anyhow!(e.to_string()))?;
  let argon=Argon2::new(Algorithm::Argon2id,Version::V0x13,params);
  let mut salt=[0u8;16];OsRng.fill_bytes(&mut salt);
  let mut key=[0u8;ARGON_OUT];argon.hash_password_into(password.as_bytes(),&salt,&mut key).map_err(|e|anyhow!(e.to_string()))?;
  let mut nonce_bytes=[0u8;12];OsRng.fill_bytes(&mut nonce_bytes);
  let nonce=Nonce::from_slice(&nonce_bytes);
  let aead=ChaCha20Poly1305::new((&key).into());
  let ts=now_ts();
  let meta=Meta{ts,mime:mime.map(|s|s.to_string()),filename:sanitize_filename(filename)};
  let mut msg_id=[0u8;16];OsRng.fill_bytes(&mut msg_id);
  let aad=aad_pwd(V,ts,meta.mime.as_deref().unwrap_or(""),meta.filename.as_deref().unwrap_or(""),&b64e(&nonce_bytes),&b64e(&msg_id));
  let framed=frame_with_padding(plaintext);
  let ct=aead.encrypt(nonce,Payload{msg:&framed,aad:&aad}).map_err(|_|anyhow!("AUTH_FAIL"))?;
  key.zeroize();
  Ok(Capsule{v:V,mode:MODE_PWD.into(),nonce_b64:b64e(&nonce_bytes),kdf:Some(Kdf{alg:"argon2id".into(),t:ARGON_T,m:ARGON_M_KIB,p:ARGON_P,salt_b64:b64e(&salt)}),meta,msg_id_b64:b64e(&msg_id),ct_b64:b64e(&ct)})
}

pub fn decrypt_password(password:&str,cap:&Capsule)->Result<Vec<u8>>{
  if cap.mode!=MODE_PWD{bail!("AUTH_FAIL")}
  let kdf=cap.kdf.as_ref().ok_or_else(||anyhow!("AUTH_FAIL"))?;
  let params=Params::new(kdf.m,kdf.t,kdf.p,Some(ARGON_OUT)).map_err(|e|anyhow!(e.to_string()))?;
  let argon=Argon2::new(Algorithm::Argon2id,Version::V0x13,params);
  let salt=b64d(&kdf.salt_b64)?;
  let mut key=[0u8;ARGON_OUT];argon.hash_password_into(password.as_bytes(),&salt,&mut key).map_err(|e|anyhow!(e.to_string()))?;
  let nonce_bytes=b64d(&cap.nonce_b64)?;if nonce_bytes.len()!=12{bail!("AUTH_FAIL")}
  let nonce=Nonce::from_slice(&nonce_bytes);
  let aad=aad_pwd(cap.v,cap.meta.ts,cap.meta.mime.as_deref().unwrap_or(""),cap.meta.filename.as_deref().unwrap_or(""),&cap.nonce_b64,&cap.msg_id_b64);
  let aead=ChaCha20Poly1305::new((&key).into());
  let ct=b64d(&cap.ct_b64)?;
  let framed=aead.decrypt(nonce,Payload{msg:&ct,aad:&aad}).map_err(|_|anyhow!("AUTH_FAIL"))?;
  let pt=deframe(framed)?;
  key.zeroize();
  Ok(pt)
}

pub fn encrypt_keypair(_sender_x25519_priv:&[u8;32],recipient_x25519_pub:&[u8;32],plaintext:&[u8],mime:Option<&str>,filename:Option<&str>,sign_ed25519_priv:Option<&[u8;32]>)->Result<CapsuleKp>{
  let eph_sec=X25519Secret::from({let mut s=[0u8;32];OsRng.fill_bytes(&mut s);s});
  let eph_pub=X25519Public::from(&eph_sec);
  let recip_pub=X25519Public::from(*recipient_x25519_pub);
  let shared=eph_sec.diffie_hellman(&recip_pub);
  let mut nonce_bytes=[0u8;12];OsRng.fill_bytes(&mut nonce_bytes);
  let mut blob1=Vec::new();blob1.extend_from_slice(b"encaps/v1|kp|");blob1.extend_from_slice(shared.as_bytes());
  let mut key=sha256(&blob1);
  let mut blob2=Vec::new();blob2.extend_from_slice(&key);blob2.extend_from_slice(&nonce_bytes);
  key=sha256(&blob2);
  let nonce=Nonce::from_slice(&nonce_bytes);
  let aead=ChaCha20Poly1305::new((&key).into());
  let ts=now_ts();
  let meta=Meta{ts,mime:mime.map(|s|s.to_string()),filename:sanitize_filename(filename)};
  let mut msg_id=[0u8;16];OsRng.fill_bytes(&mut msg_id);
  let ephem_b64=b64e(eph_pub.as_bytes());
  let kid=kid_from_pub(recipient_x25519_pub);
  let aad=aad_kp(V,&ephem_b64,&kid,ts,meta.mime.as_deref().unwrap_or(""),meta.filename.as_deref().unwrap_or(""),&b64e(&nonce_bytes),&b64e(&msg_id));
  let framed=frame_with_padding(plaintext);
  let ct=aead.encrypt(nonce,Payload{msg:&framed,aad:&aad}).map_err(|_|anyhow!("AUTH_FAIL"))?;
  let mut cap=CapsuleKp{v:V,mode:MODE_KP.into(),nonce_b64:b64e(&nonce_bytes),meta,msg_id_b64:b64e(&msg_id),ephem_pub_b64:ephem_b64,recipient_key_id:kid,sender_ed25519_pub_b64:None,sig_b64:None,ct_b64:b64e(&ct)};
  if let Some(sk32)=sign_ed25519_priv{
    let sk=SigningKey::from_bytes(sk32);
    let vk=sk.verifying_key();
    cap.sender_ed25519_pub_b64=Some(b64e(&vk.to_bytes()));
    let mut tmp=cap.clone();tmp.sig_b64=None;
    let payload=serde_json::to_vec(&tmp)?;
    let sig=sk.sign(&payload);
    cap.sig_b64=Some(b64e(sig.to_bytes().as_ref()));
  }
  key.zeroize();
  Ok(cap)
}

pub fn decrypt_keypair(recipient_x25519_priv:&[u8;32],cap:&CapsuleKp,expect_sender_ed25519_pub_b64:Option<&str>)->Result<Vec<u8>>{
  if cap.mode!=MODE_KP{bail!("AUTH_FAIL")}
  let ephem_bytes=b64d(&cap.ephem_pub_b64)?;if ephem_bytes.len()!=32{bail!("AUTH_FAIL")}
  let eph_pub=X25519Public::from(<[u8;32]>::try_from(ephem_bytes.as_slice()).map_err(|_|anyhow!("AUTH_FAIL"))?);
  let recip=X25519Secret::from(*recipient_x25519_priv);
  let shared=recip.diffie_hellman(&eph_pub);
  let nonce_bytes=b64d(&cap.nonce_b64)?;if nonce_bytes.len()!=12{bail!("AUTH_FAIL")}
  let mut blob1=Vec::new();blob1.extend_from_slice(b"encaps/v1|kp|");blob1.extend_from_slice(shared.as_bytes());
  let mut key=sha256(&blob1);
  let mut blob2=Vec::new();blob2.extend_from_slice(&key);blob2.extend_from_slice(&nonce_bytes);
  key=sha256(&blob2);
  let nonce=Nonce::from_slice(&nonce_bytes);
  let aad=aad_kp(cap.v,&cap.ephem_pub_b64,&cap.recipient_key_id,cap.meta.ts,cap.meta.mime.as_deref().unwrap_or(""),cap.meta.filename.as_deref().unwrap_or(""),&cap.nonce_b64,&cap.msg_id_b64);
  let aead=ChaCha20Poly1305::new((&key).into());
  let ct=b64d(&cap.ct_b64)?;
  let framed=aead.decrypt(nonce,Payload{msg:&ct,aad:&aad}).map_err(|_|anyhow!("AUTH_FAIL"))?;
  let pt=deframe(framed)?;
  if let Some(sig_b64)=&cap.sig_b64{
    let sig_bytes=b64d(sig_b64)?;
    let sig=Signature::from_bytes(&<[u8;64]>::try_from(sig_bytes.as_slice()).map_err(|_|anyhow!("AUTH_FAIL"))?);
    let pub_b64=cap.sender_ed25519_pub_b64.as_ref().ok_or_else(||anyhow!("AUTH_FAIL"))?;
    if let Some(expect)=expect_sender_ed25519_pub_b64{if expect!=pub_b64{bail!("AUTH_FAIL")}}
    let vk_bytes=b64d(pub_b64)?; if vk_bytes.len()!=32{bail!("AUTH_FAIL")}
    let vk=VerifyingKey::from_bytes(&<[u8;32]>::try_from(vk_bytes.as_slice()).map_err(|_|anyhow!("AUTH_FAIL"))?).map_err(|_|anyhow!("AUTH_FAIL"))?;
    let mut tmp=cap.clone();tmp.sig_b64=None;
    let payload=serde_json::to_vec(&tmp)?;
    vk.verify(&payload,&sig).map_err(|_|anyhow!("AUTH_FAIL"))?;
  }
  key.zeroize();
  Ok(pt)
}

pub fn encrypt_password_kat_with(password:&str,plaintext:&[u8],mime:Option<&str>,filename:Option<&str>,salt:[u8;16],nonce_bytes:[u8;12],msg_id:[u8;16])->Result<Capsule>{
  let params=Params::new(ARGON_M_KIB,ARGON_T,ARGON_P,Some(ARGON_OUT)).map_err(|e|anyhow!(e.to_string()))?;
  let argon=Argon2::new(Algorithm::Argon2id,Version::V0x13,params);
  let mut key=[0u8;ARGON_OUT];argon.hash_password_into(password.as_bytes(),&salt,&mut key).map_err(|e|anyhow!(e.to_string()))?;
  let nonce=Nonce::from_slice(&nonce_bytes);
  let aead=ChaCha20Poly1305::new((&key).into());
  let ts=now_ts();
  let meta=Meta{ts,mime:mime.map(|s|s.to_string()),filename:sanitize_filename(filename)};
  let n_b64=b64e(&nonce_bytes);
  let id_b64=b64e(&msg_id);
  let aad=aad_pwd(V,ts,meta.mime.as_deref().unwrap_or(""),meta.filename.as_deref().unwrap_or(""),&n_b64,&id_b64);
  let mut framed=Vec::with_capacity(4+plaintext.len());framed.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());framed.extend_from_slice(plaintext);
  let ct=aead.encrypt(nonce,Payload{msg:&framed,aad:&aad}).map_err(|_|anyhow!("AUTH_FAIL"))?;
  key.zeroize();
  Ok(Capsule{v:V,mode:MODE_PWD.into(),nonce_b64:n_b64,kdf:Some(Kdf{alg:"argon2id".into(),t:ARGON_T,m:ARGON_M_KIB,p:ARGON_P,salt_b64:b64e(&salt)}),meta,msg_id_b64:id_b64,ct_b64:b64e(&ct)})
}

pub fn encrypt_keypair_kat_with(eph_sec_bytes:[u8;32],recipient_x25519_pub:&[u8;32],plaintext:&[u8],mime:Option<&str>,filename:Option<&str>,nonce_bytes:[u8;12],msg_id:[u8;16],sign_ed25519_priv:Option<&[u8;32]>)->Result<CapsuleKp>{
  let eph_sec=X25519Secret::from(eph_sec_bytes);
  let eph_pub=X25519Public::from(&eph_sec);
  let recip_pub=X25519Public::from(*recipient_x25519_pub);
  let shared=eph_sec.diffie_hellman(&recip_pub);
  let mut blob1=Vec::new();blob1.extend_from_slice(b"encaps/v1|kp|");blob1.extend_from_slice(shared.as_bytes());
  let mut key=sha256(&blob1);
  let mut blob2=Vec::new();blob2.extend_from_slice(&key);blob2.extend_from_slice(&nonce_bytes);
  key=sha256(&blob2);
  let nonce=Nonce::from_slice(&nonce_bytes);
  let aead=ChaCha20Poly1305::new((&key).into());
  let ts=now_ts();
  let meta=Meta{ts,mime:mime.map(|s|s.to_string()),filename:sanitize_filename(filename)};
  let ephem_b64=b64e(eph_pub.as_bytes());
  let kid=kid_from_pub(recipient_x25519_pub);
  let aad=aad_kp(V,&ephem_b64,&kid,ts,meta.mime.as_deref().unwrap_or(""),meta.filename.as_deref().unwrap_or(""),&b64e(&nonce_bytes),&b64e(&msg_id));
  let mut framed=Vec::with_capacity(4+plaintext.len());framed.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());framed.extend_from_slice(plaintext);
  let ct=aead.encrypt(nonce,Payload{msg:&framed,aad:&aad}).map_err(|_|anyhow!("AUTH_FAIL"))?;
  let mut cap=CapsuleKp{v:V,mode:MODE_KP.into(),nonce_b64:b64e(&nonce_bytes),meta,msg_id_b64:b64e(&msg_id),ephem_pub_b64:ephem_b64,recipient_key_id:kid,sender_ed25519_pub_b64:None,sig_b64:None,ct_b64:b64e(&ct)};
  if let Some(sk32)=sign_ed25519_priv{
    let sk=SigningKey::from_bytes(sk32);
    let vk=sk.verifying_key();
    cap.sender_ed25519_pub_b64=Some(b64e(&vk.to_bytes()));
    let mut tmp=cap.clone();tmp.sig_b64=None;
    let payload=serde_json::to_vec(&tmp)?;
    let sig=sk.sign(&payload);
    cap.sig_b64=Some(b64e(sig.to_bytes().as_ref()));
  }
  key.zeroize();
  Ok(cap)
}
