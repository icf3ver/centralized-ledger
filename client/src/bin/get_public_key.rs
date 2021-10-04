use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{FromPrivateKey, ToPublicKey}};

const PRIVATE_KEY: &'static str = include_str!("../../private_key.pem");

fn main(){
    let sk = RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).expect("failed to get private key");
    let pk = RsaPublicKey::from(&sk);
    
    println!("{}", RsaPublicKey::to_public_key_pem(&pk).unwrap().as_str());
}