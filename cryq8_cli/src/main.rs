use clap::{Parser, Subcommand};
use anyhow::{Result,anyhow};
use std::fs;
use base64::Engine;
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{StaticSecret as X25519Secret,PublicKey as X25519Public};
use ed25519_dalek::SigningKey;
use sha2::{Sha256,Digest};
use serde_json::json;

#[derive(Parser)]
#[command(name="cryq8_cli")]
#[command(about="Encaps CLI")]
struct Cli{#[command(subcommand)]cmd:Cmd}

#[derive(Subcommand)]
enum Cmd{
  Encpwd{#[arg(long)]password:String,#[arg(long)]inp:String,#[arg(long)]out:String,#[arg(long)]mime:Option<String>,#[arg(long)]filename:Option<String>},
  Decpwd{#[arg(long)]password:String,#[arg(long)]inp:String,#[arg(long)]out:String},
  Enckp{#[arg(long)]sender_x25519_priv_b64:String,#[arg(long)]recipient_x25519_pub_b64:String,#[arg(long)]inp:String,#[arg(long)]out:String,#[arg(long)]mime:Option<String>,#[arg(long)]filename:Option<String>,#[arg(long)]sign_ed25519_priv_b64:Option<String>},
  Deckp{#[arg(long)]recipient_x25519_priv_b64:String,#[arg(long)]inp:String,#[arg(long)]out:String,#[arg(long)]expect_sender_ed25519_pub_b64:Option<String>},
  KeygenX,
  KeygenEd,
  KeygenXJson,
  KeygenEdJson,
  CodeFromEd{#[arg(long)]ed25519_pub_b64:String},
  KeyIdFromX{#[arg(long)]x25519_pub_b64:String},
  ReplayCheck{#[arg(long)]inp:String},
  ReplayAdd{#[arg(long)]inp:String}
}

fn b64e(v:&[u8])->String{base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)}
fn b64d32(s:&str)->Result<[u8;32]>{let v=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.as_bytes())?;let a:[u8;32]=v.try_into().map_err(|_|anyhow!("b64 size"))?;Ok(a)}
fn key_id_from_x(pub32:&[u8])->String{let mut h=Sha256::new();h.update(pub32);let o=h.finalize();hex::encode(&o[..4])}
fn code_from_ed(pub32:&[u8])->String{let mut h=Sha256::new();h.update(pub32);let d=h.finalize();let hexs=hex::encode(&d[..15]).to_uppercase();let mut out=String::new();for chunk in hexs.as_bytes().chunks(6){if !out.is_empty(){out.push('-');}out.push_str(std::str::from_utf8(chunk).unwrap());}out}
fn home()->std::path::PathBuf{std::env::var("HOME").map(std::path::PathBuf::from).unwrap_or_else(|_|std::path::PathBuf::from("."))}
fn replay_path()->std::path::PathBuf{let p=home().join(".encaps");let _=fs::create_dir_all(&p);p.join("replay.json")}
fn replay_load()->serde_json::Value{match fs::read_to_string(replay_path()){Ok(s)=>serde_json::from_str(&s).unwrap_or_else(|_|serde_json::json!({"set":[]})) ,Err(_)=>serde_json::json!({"set":[]})}}
fn replay_save(v:&serde_json::Value)->Result<()> {fs::write(replay_path(),serde_json::to_string_pretty(v)?)?;Ok(())}
fn capsule_msg_id(json_s:&str)->Result<String>{let v:serde_json::Value=serde_json::from_str(json_s)?;let id=v.get("msg_id_b64").and_then(|x|x.as_str()).ok_or_else(||anyhow!("msg_id"))?;Ok(id.to_string())}
fn replay_check_id(id:&str)->bool{let mut db=replay_load();let arr=db["set"].as_array_mut().unwrap();arr.iter().any(|x|x.as_str()==Some(id))}
fn replay_add_id(id:&str)->Result<()> {let mut db=replay_load();let arr=db["set"].as_array_mut().unwrap();arr.push(serde_json::Value::String(id.to_string()));if arr.len()>5000{let n=arr.len()-5000;for _ in 0..n{arr.remove(0);}}replay_save(&db)}

fn main()->Result<()>{
  let cli=Cli::parse();
  match cli.cmd{
    Cmd::Encpwd{password,inp,out,mime,filename} => {
      let data=fs::read(inp)?;
      let cap=cryq8::encrypt_password(&password,&data,mime.as_deref(),filename.as_deref())?;
      fs::write(out,serde_json::to_string_pretty(&cap)?)?;
      println!("OK");
    }
    Cmd::Decpwd{password,inp,out} => {
      let s=fs::read_to_string(&inp)?;
      let id=capsule_msg_id(&s)?;
      if replay_check_id(&id){return Err(anyhow!("DUPReplay"))}
      let cap:cryq8::Capsule=serde_json::from_str(&s)?;
      let pt=cryq8::decrypt_password(&password,&cap)?;
      fs::write(out,pt)?;
      replay_add_id(&id)?;
      println!("OK");
    }
    Cmd::Enckp{sender_x25519_priv_b64,recipient_x25519_pub_b64,inp,out,mime,filename,sign_ed25519_priv_b64} => {
      let s_priv=b64d32(&sender_x25519_priv_b64)?;
      let r_pub=b64d32(&recipient_x25519_pub_b64)?;
      let sig=match sign_ed25519_priv_b64{Some(x)=>Some(b64d32(&x)?),None=>None};
      let data=fs::read(inp)?;
      let cap=cryq8::encrypt_keypair(&s_priv,&r_pub,&data,mime.as_deref(),filename.as_deref(),sig.as_ref())?;
      fs::write(out,serde_json::to_string_pretty(&cap)?)?;
      println!("OK");
    }
    Cmd::Deckp{recipient_x25519_priv_b64,inp,out,expect_sender_ed25519_pub_b64} => {
      let r_priv=b64d32(&recipient_x25519_priv_b64)?;
      let s=fs::read_to_string(&inp)?;
      let id=capsule_msg_id(&s)?;
      if replay_check_id(&id){return Err(anyhow!("DUPReplay"))}
      let cap:cryq8::CapsuleKp=serde_json::from_str(&s)?;
      let exp=expect_sender_ed25519_pub_b64.as_deref();
      let pt=cryq8::decrypt_keypair(&r_priv,&cap,exp)?;
      fs::write(out,pt)?;
      replay_add_id(&id)?;
      println!("OK");
    }
    Cmd::KeygenX => {
      let mut bytes=[0u8;32];rand::thread_rng().fill_bytes(&mut bytes);
      let sec=X25519Secret::from(bytes);
      let pubk=X25519Public::from(&sec);
      println!("x25519_priv_b64={}",b64e(sec.to_bytes().as_ref()));
      println!("x25519_pub_b64={}",b64e(pubk.as_bytes()));
      println!("key_id={}",key_id_from_x(pubk.as_bytes()));
    }
    Cmd::KeygenEd => {
      let mut rng=OsRng;
      let sk=SigningKey::generate(&mut rng);
      let vk=sk.verifying_key();
      println!("ed25519_priv_b64={}",b64e(&sk.to_bytes()));
      println!("ed25519_pub_b64={}",b64e(&vk.to_bytes()));
      println!("verify_code={}",code_from_ed(&vk.to_bytes()));
    }
    Cmd::KeygenXJson => {
      let mut bytes=[0u8;32];rand::thread_rng().fill_bytes(&mut bytes);
      let sec=X25519Secret::from(bytes);
      let pubk=X25519Public::from(&sec);
      let j=json!({
        "x25519_priv_b64": b64e(sec.to_bytes().as_ref()),
        "x25519_pub_b64": b64e(pubk.as_bytes()),
        "key_id": key_id_from_x(pubk.as_bytes())
      });
      println!("{}",serde_json::to_string_pretty(&j)?);
    }
    Cmd::KeygenEdJson => {
      let mut rng=OsRng;
      let sk=SigningKey::generate(&mut rng);
      let vk=sk.verifying_key();
      let j=json!({
        "ed25519_priv_b64": b64e(&sk.to_bytes()),
        "ed25519_pub_b64": b64e(&vk.to_bytes()),
        "verify_code": code_from_ed(&vk.to_bytes())
      });
      println!("{}",serde_json::to_string_pretty(&j)?);
    }
    Cmd::CodeFromEd{ed25519_pub_b64} => {
      let v=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(ed25519_pub_b64.as_bytes())?;
      println!("{}",code_from_ed(&v));
    }
    Cmd::KeyIdFromX{x25519_pub_b64} => {
      let v=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x25519_pub_b64.as_bytes())?;
      println!("{}",key_id_from_x(&v));
    }
    Cmd::ReplayCheck{inp} => {
      let s=fs::read_to_string(inp)?;
      let id=capsule_msg_id(&s)?;
      if replay_check_id(&id){println!("DUP")}else{println!("OK")}
    }
    Cmd::ReplayAdd{inp} => {
      let s=fs::read_to_string(inp)?;
      let id=capsule_msg_id(&s)?;
      replay_add_id(&id)?;
      println!("OK")
    }
  }
  Ok(())
}
