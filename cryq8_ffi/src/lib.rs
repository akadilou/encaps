use sha2::Digest;
use anyhow::Result;
use base64::Engine;
use libc::{c_char,size_t};
use std::{ffi::CStr,ptr,slice};
use x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519Public};

fn cstr(p:*const c_char)->Result<String>{
    if p.is_null(){return Ok(String::new())}
    Ok(unsafe{CStr::from_ptr(p)}.to_str()?.to_string())
}
fn alloc_out(buf:&[u8],out:*mut *mut u8,out_len:*mut size_t)->i32{
    if out.is_null()||out_len.is_null(){return -2}
    let n=buf.len();
    let p=unsafe{libc::malloc(n)} as *mut u8;
    if p.is_null(){return -3}
    unsafe{ptr::copy_nonoverlapping(buf.as_ptr(),p,n);*out=p;*out_len=n as size_t;}
    0
}

#[no_mangle]
pub extern "C" fn q8_free(p:*mut u8,_len:size_t){
    if p.is_null(){return}
    unsafe{libc::free(p as *mut libc::c_void);}
}

#[no_mangle]
pub extern "C" fn q8_encpwd_json(
    password:*const c_char,
    data:*const u8,data_len:size_t,
    mime:*const c_char,
    filename:*const c_char,
    out_json:*mut *mut u8,out_len:*mut size_t
)->i32{
    let pass=match cstr(password){Ok(v)=>v,Err(_)=>return -10};
    let m=match cstr(mime){Ok(v)=>if v.is_empty(){None}else{Some(v)} ,Err(_)=>None};
    let f=match cstr(filename){Ok(v)=>if v.is_empty(){None}else{Some(v)} ,Err(_)=>None};
    let pt=if data.is_null(){&[][..]}else{unsafe{slice::from_raw_parts(data,data_len as usize)}};
    let cap=match cryq8::encrypt_password(&pass,pt,m.as_deref(),f.as_deref()){Ok(c)=>c,Err(_)=>return -11};
    let js=match serde_json::to_vec(&cap){Ok(v)=>v,Err(_)=>return -12};
    alloc_out(&js,out_json,out_len)
}

#[no_mangle]
pub extern "C" fn q8_decpwd_json(
    password:*const c_char,
    cap_json:*const u8,cap_len:size_t,
    out_data:*mut *mut u8,out_len:*mut size_t
)->i32{
    let pass=match cstr(password){Ok(v)=>v,Err(_)=>return -20};
    if cap_json.is_null(){return -21}
    let by=unsafe{slice::from_raw_parts(cap_json,cap_len as usize)};
    let cap:cryq8::Capsule=match serde_json::from_slice(by){Ok(v)=>v,Err(_)=>return -22};
    let pt=match cryq8::decrypt_password(&pass,&cap){Ok(v)=>v,Err(_)=>return -23};
    alloc_out(&pt,out_data,out_len)
}

#[no_mangle]
pub extern "C" fn q8_enckp_json(
    sender_x_priv_b64:*const c_char,
    recip_x_pub_b64:*const c_char,
    data:*const u8,data_len:size_t,
    mime:*const c_char,
    filename:*const c_char,
    sign_ed_priv_b64:*const c_char,
    out_json:*mut *mut u8,out_len:*mut size_t
)->i32{
    let s_priv_b64=match cstr(sender_x_priv_b64){Ok(v)=>v,Err(_)=>return -30};
    let r_pub_b64=match cstr(recip_x_pub_b64){Ok(v)=>v,Err(_)=>return -31};
    let s_priv=match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s_priv_b64){Ok(v)=>v,Err(_)=>return -32};
    let r_pub=match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(r_pub_b64){Ok(v)=>v,Err(_)=>return -33};
    if s_priv.len()!=32||r_pub.len()!=32{return -34}
    let s_priv_arr:[u8;32]=match s_priv.try_into(){Ok(a)=>a,Err(_)=>return -35};
    let r_pub_arr:[u8;32]=match r_pub.try_into(){Ok(a)=>a,Err(_)=>return -36};
    let sig = if sign_ed_priv_b64.is_null(){None}else{
        match cstr(sign_ed_priv_b64){
            Ok(v)=>{
                if v.is_empty(){None}else{
                    let d=match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v){Ok(v)=>v,Err(_)=>return -37};
                    if d.len()!=32{return -38}
                    let a:[u8;32]=match d.try_into(){Ok(a)=>a,Err(_)=>return -39};
                    Some(a)
                }
            },
            Err(_)=>None
        }
    };
    let m=match cstr(mime){Ok(v)=>if v.is_empty(){None}else{Some(v)} ,Err(_)=>None};
    let f=match cstr(filename){Ok(v)=>if v.is_empty(){None}else{Some(v)} ,Err(_)=>None};
    let pt=if data.is_null(){&[][..]}else{unsafe{slice::from_raw_parts(data,data_len as usize)}};
    let cap=match cryq8::encrypt_keypair(&s_priv_arr,&r_pub_arr,pt,m.as_deref(),f.as_deref(),sig.as_ref()){Ok(c)=>c,Err(_)=>return -40};
    let js=match serde_json::to_vec(&cap){Ok(v)=>v,Err(_)=>return -41};
    alloc_out(&js,out_json,out_len)
}

#[no_mangle]
pub extern "C" fn q8_deckp_json(
    recip_x_priv_b64:*const c_char,
    cap_json:*const u8,cap_len:size_t,
    expect_ed_pub_b64:*const c_char,
    out_data:*mut *mut u8,out_len:*mut size_t
)->i32{
    let r_priv_b64=match cstr(recip_x_priv_b64){Ok(v)=>v,Err(_)=>return -50};
    let r_priv=match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(r_priv_b64){Ok(v)=>v,Err(_)=>return -51};
    if r_priv.len()!=32{return -52}
    let r_priv_arr:[u8;32]=match r_priv.try_into(){Ok(a)=>a,Err(_)=>return -53};
    if cap_json.is_null(){return -54}
    let cap_by=unsafe{slice::from_raw_parts(cap_json,cap_len as usize)};
    let cap:cryq8::CapsuleKp=match serde_json::from_slice(cap_by){Ok(v)=>v,Err(_)=>return -55};
    let exp=if expect_ed_pub_b64.is_null(){None}else{
        match cstr(expect_ed_pub_b64){Ok(v)=>if v.is_empty(){None}else{Some(v)},Err(_)=>None}
    };
    let pt=match cryq8::decrypt_keypair(&r_priv_arr,&cap,exp.as_deref()){Ok(v)=>v,Err(_)=>return -56};
    alloc_out(&pt,out_data,out_len)
}

#[no_mangle]
pub extern "C" fn q8_keygen_x_json(out_json:*mut *mut u8,out_len:*mut size_t)->i32{
    use rand::RngCore;
    let mut sec=[0u8;32]; rand::thread_rng().fill_bytes(&mut sec);
    let pubk = X25519Public::from(&X25519Secret::from(sec));
    let mut hasher=sha2::Sha256::new(); hasher.update(pubk.as_bytes());
    let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hasher.finalize()[..4]);
    let j=serde_json::json!({
        "x25519_priv_b64": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sec),
        "x25519_pub_b64":  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubk.as_bytes()),
        "key_id": kid
    });
    let out=serde_json::to_vec(&j).unwrap();
    alloc_out(&out,out_json,out_len)
}

#[no_mangle]
pub extern "C" fn q8_keygen_ed_json(out_json:*mut *mut u8,out_len:*mut size_t)->i32{
    use rand::rngs::OsRng;
    let mut rng=OsRng;
    let sk=ed25519_dalek::SigningKey::generate(&mut rng);
    let vk=sk.verifying_key();
    let j=serde_json::json!({
        "ed25519_priv_b64": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sk.to_bytes()),
        "ed25519_pub_b64":  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&vk.to_bytes())
    });
    let out=serde_json::to_vec(&j).unwrap();
    alloc_out(&out,out_json,out_len)
}
