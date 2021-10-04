use std::net::{TcpStream};
use std::io::{self, Read, Write};
use rsa::pkcs8::FromPrivateKey;
use sha2::Digest;
use std::str::from_utf8;
use rsa::{PublicKey, RsaPublicKey, RsaPrivateKey, PaddingScheme};

const PRIVATE_KEY: &'static str = include_str!("../../private_key.pem");
const SERVER: &'static str = "localhost:3333";

fn main() -> Result<(), io::Error> {
    println!("Uname:");
    let mut uname = String::new(); 
    io::stdin().read_line(&mut uname)?;

    println!("To:");
    let mut dest = String::new(); 
    io::stdin().read_line(&mut dest)?;
    
    println!("amount:");
    let mut amount = String::new(); 
    io::stdin().read_line(&mut amount)?;

    let transaction = format!("{:44}", format!("{} {} {}", uname.trim(), dest.trim(), amount.trim()));

    println!("Please verify the transaction:\n{:44}", transaction);
    println!("[y/N]:");
    let mut approved = String::new();
    io::stdin().read_line(&mut approved)?;
    let approved = approved.trim();

    if approved == "y" || approved == "Y" {
        make_transaction(&transaction);
    }
    Ok(())
}

fn make_transaction(msg: &str) {
    match TcpStream::connect(SERVER) {
        Ok(mut stream) => {
            println!("Successfully connected");

            // Sign
            let sk = RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).expect("failed to get private key");
            let pk = RsaPublicKey::from(&sk);

            let data = msg.as_bytes();
            let hash: &[u8] = &sha2::Sha512::digest(&data[..])[..];
            let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_512));
            let signature = sk.sign(padding, &hash).expect("failed to sign");
            
            // Check Signature
            let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_512));
            pk.verify(padding, &hash, &signature)
                .expect("Signature Not Valid");
            
            // send signature and message
            let msg: &[u8] = &[data, &signature[..]].concat()[..];
            println!("{:?}", msg.len());
            stream.write(msg).unwrap();

            println!("Sent transaction, awaiting confirmation...");

            let mut data = [0 as u8; 2];
            match stream.read_exact(&mut data) {
                Ok(_) => {
                    if &data[..2] == b"GO" {
                        println!("Success");
                    } else if &data[..2] == b"NO" {
                        println!("Failure");
                    } else {
                        let text = from_utf8(&data).unwrap();
                        println!("Unexpected reply: {}", text);
                    }
                },
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                }
            }
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}
