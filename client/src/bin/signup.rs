use std::{io::{self, Read, Write}, net::TcpStream, str::from_utf8};
// use rpassword::read_password;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{FromPrivateKey, ToPublicKey}};

const PRIVATE_KEY: &'static str = include_str!("../../private_key.pem");
const SERVER: &'static str = "localhost:5555";


fn main() -> Result<(), io::Error> {
    let mut uname = String::new();
    while {
        print!("Username: ");
        std::io::stdout().flush().unwrap();
        io::stdin().read_line(&mut uname)?;
        uname = uname.trim().to_owned();
        // Rust does not allow for regex without dependencies
        uname.len() > 18 || uname.to_lowercase().chars().any(|c| { match c { 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm' | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z' => false, _ => true } })
    } { println!("Please make sure the username does not contain any special characters and is no longer than 18 characters."); }

    // let mut key_path = String::new();
    // while {
    //     print!("Key Path: ");
    //     std::io::stdout().flush().unwrap();
    //     io::stdin().read_line(&mut uname)?;
    //     key_path = uname.trim().to_owned();
    //     // Rust does not allow for regex without dependencies
    //     !std::path::Path::new(&key_path).exists()
    // } { println!("Could not find your key at the inputted location."); }

    // let mut passwd;
    // while {
    //     print!("Password: ");
    //     std::io::stdout().flush().unwrap();
    //     passwd = read_password().unwrap();
        
    //     print!("Retype Password: ");
    //     std::io::stdout().flush().unwrap();
    //     passwd != read_password().unwrap()
    // } { println!("The passwords do not match."); }

    let sk = RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).expect("failed to get private key");

    // TODO: secure sk locally

    let pk = RsaPublicKey::from(&sk);
    let der_pk = RsaPublicKey::to_public_key_der(&pk).unwrap();
    let der_pk_bytes: &[u8] = der_pk.as_ref();
    assert_eq!(der_pk_bytes.len(), 294);
    
    print!("To confirm creation of this account reentering the username: ");
    let mut confirmation = String::new();
    std::io::stdout().flush().unwrap();
    io::stdin().read_line(&mut confirmation)?;
    confirmation = confirmation.trim().to_owned();

    if confirmation == uname {
        let mut msg: [u8; 315] = [0; 315];
        let (raw_ty_uname, raw_pk) = msg.split_at_mut(21);
        raw_ty_uname.copy_from_slice(format!("ACC{:18}", uname).as_bytes());
        raw_pk.copy_from_slice(der_pk_bytes);
        send_pk(&msg);
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

fn send_pk(msg: &[u8]) {
    match TcpStream::connect(SERVER) {
        Ok(mut stream) => {
            println!("Successfully connected");

            stream.write(msg).unwrap();

            println!("Sent request, awaiting confirmation...");

            let mut confirmation = [0_u8; 3];
            match stream.read_exact(&mut confirmation) {
                Ok(_) => {
                    match &confirmation {
                        b"OK " => { println!("Confirmation Received. Success"); },

                        // Errors
                        b"E06" => { println!("Error 06: A user with a similar username already exists please pick another username."); },

                        other => {
                            let text = from_utf8(other).unwrap();
                            println!("Unexpected reply: {}", text);
                        },
                    }
                },
                Err(e) => {
                    println!("Failed to receive confirmation: {}", e);
                }
            }
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}