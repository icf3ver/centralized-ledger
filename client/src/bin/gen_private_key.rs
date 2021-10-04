use rand::rngs::OsRng;
use rsa::pkcs8::ToPrivateKey;
use rsa::RsaPrivateKey;

fn main(){
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    println!("{:?}", private_key.to_pkcs8_pem())
}
