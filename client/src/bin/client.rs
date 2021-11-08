use std::net::{TcpStream};
use std::io::{self, Read, Write};
use rsa::pkcs8::FromPrivateKey;
use sha2::Digest;
use std::str::from_utf8;
use rsa::{PublicKey, RsaPublicKey, RsaPrivateKey, PaddingScheme};

const PRIVATE_KEY: &'static str = include_str!("../../private_key.pem");
const SERVER: &'static str = "localhost:5555";

fn user_verify_nonaction(ty: &[u8; 3], msg: &str) -> Result<[u8; 53], io::Error> {
    println!("Please verify the request:\n{:50}", msg);
    println!("Is this correct? [y/N]:");
    let mut approved = String::new();
    io::stdin().read_line(&mut approved)?;
    let approved = approved.trim();

    if approved.to_uppercase() == "Y" {
        let mut output: [u8; 53] = [0; 53];
        let (otyp, request) = output.split_at_mut(3);
        otyp.copy_from_slice(ty);
        request.copy_from_slice(msg.as_bytes());
        Ok(output)
    } else {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

fn user_verify_action(ty: &[u8; 3], msg: &str) -> Result<[u8; 303], io::Error> {
    fn sign_action(ty: &[u8; 3], msg: &str) -> [u8; 303] {
        let mut signed_msg: [u8; 303] = [0_u8; 303];
        let (otyp, inner) = signed_msg.split_at_mut(3);
        otyp.copy_from_slice(ty);
        let (dat, sig) = inner.split_at_mut(44);

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

        // println!("{}", unsafe {std::str::from_utf8_unchecked(&signature[..])}); // unique id gen
        
        // copy slices into output
        dat.copy_from_slice(data);
        sig.copy_from_slice(&signature);

        signed_msg
    }

    println!("Please confirm the ACTION:\n{:44}", msg); // TODO: checksize
    println!("Is this correct? [y/N]:");
    let mut approved = String::new();
    io::stdin().read_line(&mut approved)?;
    let approved = approved.trim();

    if approved.to_uppercase() == "Y" {
        Ok(sign_action(ty, &msg))
    } else {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

fn _get_next_action_id() -> Result<(), ()> {
    todo!()
}

fn main() -> Result<(), io::Error> {
    while {
        println!("Request Type:");
        let mut request_type = String::new(); 
        io::stdin().read_line(&mut &mut request_type)?;
        request_type = request_type.to_uppercase();
        
        match request_type.as_str().trim() {
            "SEN" => {
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
                let verification = user_verify_action(b"SEN", &transaction);

                if let Ok(msg) = verification {
                    make_request(&msg, false);
                } else {
                    println!("Transaction NOT Sent.");
                }
            }
            "BAL" => {
                println!("Uname :");
                let mut uname = String::new(); 
                io::stdin().read_line(&mut uname)?;

                let request = format!("{:50}", uname.trim());
                let verification = user_verify_nonaction(b"BAL", &request);

                if let Ok(msg) = verification {
                    make_request(&msg, true);
                } else {
                    println!("Balance request NOT sent.");
                }
            },
            "OWE" => {
                println!("<Uname> Owes (* for everyone):");
                let mut owes = String::new(); 
                io::stdin().read_line(&mut owes)?;
            
                println!("To <Uname> (* for everyone):");
                let mut to = String::new(); 
                io::stdin().read_line(&mut to)?;

                let request = format!("{:50}", format!("{} {}", owes.trim(), to.trim()));
                let verification = user_verify_nonaction(b"OWE", &request);

                if let Ok(msg) = verification {
                    make_request(&msg, true);
                } else {
                    println!("Debt request NOT sent.");
                }
            },
            other => {
                eprintln!("{} is not a valid request.", other);
            }
        }

        // Another Request?
        println!("Would You like to make another request? [y/N]: ");
    
        let mut approved = String::new();
        io::stdin().read_line(&mut approved)?;
        let approved = approved.trim();
    
        approved.to_uppercase() == "Y"
    } {}

    Ok(())
}


fn make_request(msg: &[u8], await_data: bool) {
    match TcpStream::connect(SERVER) {
        Ok(mut stream) => {
            println!("Successfully connected");

            stream.write(msg).unwrap();

            println!("Sent request, awaiting confirmation...");

            let mut confirmation = [0_u8; 2];
            match stream.read_exact(&mut confirmation) {
                Ok(_) => {
                    match (&confirmation, await_data) {
                        (b"GO", true) => {
                            println!("Received Confirmation, awaiting data...");
                            let mut data = [0_u8; 8];
                            match stream.read_exact(&mut data) {
                                Ok(_) => {
                                    println!("Answer: {}", i64::from_be_bytes(data));
                                },
                                Err(e) => {
                                    println!("Failed to receive data: {}", e);
                                }
                            }
                        },
                        (b"GO", false) => {
                            println!("Success");
                        },
                        (b"NO", _) => {
                            println!("Failure");
                        },
                        (other, _) => {
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
    println!("Terminated.");
}
