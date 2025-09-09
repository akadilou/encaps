use clap::{Parser, Subcommand};
use anyhow::{Result,anyhow};
use std::fs;
use base64::Engine;
use rand::{rngs::OsRng};
use x25519_dalek::{StaticSecret as X25519Secret,PublicKey as X25519Public};
use ed25519_dalek::SigningKey;
use sha2::{Sha256,Digest};

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
  CodeFromEd{#[arg(long)]ed25519_pub_b64:String},
  KeyIdFromX{#[arg(long)]x25519_pub_b64:String},
  QrEncode{#[arg(long)]inp:String,#[arg(long)]out_png:String,#[arg(long, default_value="M")]ecc:String},
  QrSplit{#[arg(long)]inp:String,#[arg(long)]out_dir:String,#[arg(long, default_value_t=900)]chunk:usize,#[arg(long, default_value="M")]ecc:String},
  QrJoin{#[arg(long)]dir:String,#[arg(long)]out:String}
}

fn b64e(v:&[u8])->String{base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)}
fn b64d32(s:&str)->Result<[u8;32]>{let v=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.as_bytes())?;let a:[u8;32]=v.try_into().map_err(|_|anyhow!("b64 size"))?;Ok(a)}
fn key_id_from_x(pub32:&[u8])->String{let mut h=Sha256::new();h.update(pub32);let o=h.finalize();hex::encode(&o[..4])}
fn code_from_ed(pub32:&[u8])->String{let mut h=Sha256::new();h.update(pub32);let d=h.finalize();let hexs=hex::encode(&d[..15]).to_uppercase();let mut out=String::new();for chunk in hexs.as_bytes().chunks(6){if !out.is_empty(){out.push('-');}out.push_str(std::str::from_utf8(chunk).unwrap());}out}
fn ecc_level(s:&str)->qrcode::EcLevel{use qrcode::EcLevel;match s{"L"=>EcLevel::L,"M"=>EcLevel::M,"Q"=>EcLevel::Q,"H"=>EcLevel::H,_=>EcLevel::M}}

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
      let s=fs::read_to_string(inp)?;
      let cap:cryq8::Capsule=serde_json::from_str(&s)?;
      let pt=cryq8::decrypt_password(&password,&cap)?;
      fs::write(out,pt)?;
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
      let s=fs::read_to_string(inp)?;
      let cap:cryq8::CapsuleKp=serde_json::from_str(&s)?;
      let exp=expect_sender_ed25519_pub_b64.as_deref();
      let pt=cryq8::decrypt_keypair(&r_priv,&cap,exp)?;
      fs::write(out,pt)?;
      println!("OK");
    }
    Cmd::KeygenX => {
      let sec=X25519Secret::random_from_rng(OsRng);
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
    Cmd::CodeFromEd{ed25519_pub_b64} => {
      let v=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(ed25519_pub_b64.as_bytes())?;
      println!("{}",code_from_ed(&v));
    }
    Cmd::KeyIdFromX{x25519_pub_b64} => {
      let v=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x25519_pub_b64.as_bytes())?;
      println!("{}",key_id_from_x(&v));
    }
    Cmd::QrEncode{inp,out_png,ecc} => {
      use std::fs::File;
      use qrcode::QrCode;
      use image::{Luma,ImageBuffer,DynamicImage,ImageOutputFormat};
      let data = fs::read_to_string(inp)?;
      let level = ecc_level(&ecc);
      let code = QrCode::with_error_correction_level(data.as_bytes(), level)?;
      let img = code.render::<Luma<u8>>().min_dimensions(512,512).build();
      let dynimg = DynamicImage::ImageLuma8(ImageBuffer::from_raw(img.width(), img.height(), img.into_raw()).ok_or_else(||anyhow!("img"))?);
      let mut f = File::create(out_png)?;
      dynimg.write_to(&mut f, ImageOutputFormat::Png)?;
      println!("OK");
    }
    Cmd::QrSplit{inp,out_dir,chunk,ecc} => {
      use std::fs::File;
      use qrcode::QrCode;
      use image::{Luma,ImageBuffer,DynamicImage,ImageOutputFormat};
      use uuid::Uuid;
      fs::create_dir_all(&out_dir)?;
      let data = fs::read_to_string(inp)?;
      let id = Uuid::new_v4().to_string()[..8].to_string();
      let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data.as_bytes());
      let total = b64.len().div_ceil(chunk);
      let level = ecc_level(&ecc);
      for (i,sub) in b64.as_bytes().chunks(chunk).enumerate(){
        let head = format!("Q8QR|{}|{}/{}|",id,i+1,total);
        let payload = [head.as_bytes(),sub].concat();
        let code = QrCode::with_error_correction_level(&payload, level)?;
        let img = code.render::<Luma<u8>>().min_dimensions(512,512).build();
        let dynimg = DynamicImage::ImageLuma8(ImageBuffer::from_raw(img.width(), img.height(), img.into_raw()).ok_or_else(||anyhow!("img"))?);
        let path = format!("{}/{}_{:03}.png", out_dir, id, i+1);
        let mut f = File::create(path)?;
        dynimg.write_to(&mut f, ImageOutputFormat::Png)?;
      }
      println!("OK {} parts", total);
    }
    Cmd::QrJoin{dir,out} => {
      use std::collections::HashMap;
      let mut groups: HashMap<String, Vec<(usize,usize,String)>> = HashMap::new();
      for entry in fs::read_dir(&dir)?{
        let p=entry?.path();
        if p.extension().and_then(|e|e.to_str())!=Some("png"){continue}
        let img=image::open(&p)?.to_luma8();
        let mut prep=rqrr::PreparedImage::prepare(img);
        let grids=prep.detect_grids();
        if grids.is_empty(){continue}
        let (_meta,bytes)=match grids[0].decode(){Ok(x)=>x,Err(_)=>continue};
        let s=bytes;
        if !s.starts_with("Q8QR|"){continue}
        let mut it=s.splitn(4,'|');
        let _tag=it.next().unwrap();
        let id=it.next().unwrap().to_string();
        let idx_total=it.next().unwrap();
        let payload=it.next().unwrap_or("").to_string();
        let mut it2=idx_total.split('/');
        let idx:usize=match it2.next().unwrap().parse(){Ok(v)=>v,Err(_)=>continue};
        let total:usize=match it2.next().unwrap().parse(){Ok(v)=>v,Err(_)=>continue};
        groups.entry(id).or_default().push((idx,total,payload));
      }
      if groups.is_empty(){return Err(anyhow!("no parts"))}
      let (best_id, mut parts) = groups.into_iter().max_by_key(|(_,v)| v.len()).unwrap();
      parts.sort_by_key(|(i,_,_)|*i);
      let total = parts.first().ok_or_else(||anyhow!("no parts"))?.1;
      if parts.len()!=total { return Err(anyhow!("missing parts")); }
      let mut by_idx = vec![String::new(); total+1];
      for (i,t,p) in parts {
        if t!=total { return Err(anyhow!("mismatch")); }
        if i>=by_idx.len() { return Err(anyhow!("index out of range")); }
        by_idx[i]=p;
      }
      let mut b64 = String::new();
      for (i,p) in by_idx.iter().enumerate().skip(1).take(total) {
        if p.is_empty(){ return Err(anyhow!("missing part {}", i)); }
        b64.push_str(p);
      }
      let data=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64.as_bytes())?;
      fs::write(out,data)?;
      println!("OK {}", best_id);
    }
  }
  Ok(())
}
