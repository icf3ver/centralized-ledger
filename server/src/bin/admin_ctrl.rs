use std::{fs::File, io::{self, Read, Write}};
use rsa::pkcs8::FromPublicKey;
use rsa::RsaPublicKey;
use serde::{Serialize, Deserialize};

const USR_DIR: &'static str = "./server/usr_dir";

#[derive(Debug, Serialize, Deserialize)]
struct User<'a>{
    uname: &'a str,
    public_key: RsaPublicKey,
    bal: usize,
}

fn main() -> Result<(), io::Error> {
    println!("Uname:");
    let mut uname = String::new(); 
    io::stdin().read_line(&mut uname)?;

    println!("path to public key:");
    let mut public_key_path = String::new(); 
    io::stdin().read_line(&mut public_key_path)?;
    let public_key = &mut [0_u8; 450];
    File::open(public_key_path).unwrap().read(public_key).unwrap();
    let inner = std::str::from_utf8(public_key).unwrap();
    println!("{}", inner);
    let public_key = RsaPublicKey::from_public_key_pem(inner).expect("todo");
    
    println!("{}/{}.txt", USR_DIR, uname.trim());
    let mut file = File::create(format!("{}/{}.txt", USR_DIR, uname))?;
    file.write_all(&bincode::serialize(&User { uname: &uname, public_key, bal: 0 }).expect("todo")[..])?;
    Ok(())
}
