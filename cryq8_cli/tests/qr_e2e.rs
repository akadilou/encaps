use std::process::Command;
use std::fs;
use tempfile::tempdir;

fn run(args: &[&str]) {
    let st = Command::new("cargo")
        .args(["run","--quiet","--release","-p","cryq8_cli","--"])
        .args(args)
        .status()
        .unwrap();
    assert!(st.success(), "command failed: {:?}", args);
}

#[test]
fn qr_split_join_decrypt_roundtrip() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let plain = root.join("plain.txt");
    let cap = root.join("cap.q8msg");
    let out = root.join("out.txt");
    let qrs = root.join("qrs");
    fs::create_dir_all(&qrs).unwrap();

    fs::write(&plain, b"qr e2e test").unwrap();

    run(&["encpwd","--password","P@ss",
        "--inp", plain.to_str().unwrap(),
        "--out", cap.to_str().unwrap(),
        "--mime","text/plain","--filename","plain.txt"]);

    run(&["qr-split","--inp", cap.to_str().unwrap(),
        "--out-dir", qrs.to_str().unwrap(),"--chunk","900","--ecc","M"]);

    run(&["qr-join","--dir", qrs.to_str().unwrap(),
        "--out", cap.to_str().unwrap()]);

    run(&["decpwd","--password","P@ss",
        "--inp", cap.to_str().unwrap(),
        "--out", out.to_str().unwrap()]);

    let a = fs::read(&plain).unwrap();
    let b = fs::read(&out).unwrap();
    assert_eq!(a, b);
}
