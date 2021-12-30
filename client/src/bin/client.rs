use std::collections::VecDeque;
use std::iter::FromIterator;
use std::net::{TcpStream};
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::rngs::OsRng;
use rsa::pkcs8::{FromPrivateKey, FromPublicKey};
use sha2::Digest;
use rsa::{PublicKey, RsaPublicKey, RsaPrivateKey, PaddingScheme};

const PRIVATE_KEY: &'static str = include_str!("../../private_key.pem");
const SERVER: &'static str = "localhost:5555";

fn user_verify_nonaction(ty: &[u8; 3], msg: &str) -> Result<[u8; 51], io::Error> {
    println!("Please verify the request: \n > {:48}", msg);
    print!("Is this correct? [y/N]: ");
    let mut approved = String::new();
    std::io::stdout().flush().unwrap();
    io::stdin().read_line(&mut approved)?;
    let approved = approved.trim();

    if approved.to_uppercase() == "Y" {
        let mut output: [u8; 51] = [0; 51];
        let (otyp, request) = output.split_at_mut(3);
        otyp.copy_from_slice(ty);
        request.copy_from_slice(msg.as_bytes());
        Ok(output)
    } else {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

fn user_verify_action(ty: &[u8; 3], msg: &str) -> Result<[u8; 315], io::Error> {
    fn sign_action(ty: &[u8; 3], msg: &str) -> [u8; 315] {
        let mut signed_msg: [u8; 315] = [0_u8; 315];
        let (otyp, inner) = signed_msg.split_at_mut(3);
        otyp.copy_from_slice(ty);
        let (dat, sig) = inner.split_at_mut(56);

        // Sign
        let sk = RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).expect("failed to get private key");
        let pk = RsaPublicKey::from(&sk);

        let timestamped_msg = [&timestamp()[..], msg.as_bytes()].concat();

        let hash: &[u8] = &sha2::Sha512::digest(&timestamped_msg[..])[..];
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_512));
        let signature = sk.sign(padding, &hash).expect("failed to sign");
        
        // Check Signature
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_512));
        pk.verify(padding, &hash, &signature)
            .expect("Signature Not Valid");

        // println!("{}", unsafe {std::str::from_utf8_unchecked(&signature[..])}); // unique id gen
        
        // copy slices into output
        dat.copy_from_slice(&timestamped_msg[..]);
        sig.copy_from_slice(&signature);

        signed_msg
    }

    println!("Please confirm the ACTION: \n > {:48}", msg); // TODO: checksize
    print!("Is this correct? [y/N]: ");
    let mut approved = String::new();
    std::io::stdout().flush().unwrap();
    io::stdin().read_line(&mut approved)?;
    let approved = approved.trim();

    if approved.to_uppercase() == "Y" {
        Ok(sign_action(ty, &msg))
    } else {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

/// Time the best ID system
/// At the moment the max unix 
/// time stamp is a 32 bit integer 
/// but I will use 64 bits because 
/// it can never fail.
fn timestamp() -> [u8; 8] {
    let time = SystemTime::now();
    let seconds_since_epoch = time.duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch").as_secs();
    seconds_since_epoch.to_be_bytes()
}

fn main() -> Result<(), io::Error> {
    while {
        print!("Request Type: ");
        let mut request_type = String::new(); 
        std::io::stdout().flush().unwrap();
        io::stdin().read_line(&mut &mut request_type)?;
        request_type = request_type.to_uppercase();
        
        match request_type.as_str().trim() {
            "SEN" => {
                print!("Uname: ");
                let mut uname = String::new(); 
                std::io::stdout().flush().unwrap();
                io::stdin().read_line(&mut uname)?;
            
                print!("To: ");
                let mut dest = String::new(); 
                std::io::stdout().flush().unwrap();
                io::stdin().read_line(&mut dest)?;
                
                print!("amount: ");
                let mut amount = String::new(); 
                std::io::stdout().flush().unwrap();
                io::stdin().read_line(&mut amount)?;

                let transaction = format!("{:18} {:18} {:10}", uname.trim(), dest.trim(), amount.trim());
                let verification = user_verify_action(b"SEN", &transaction);

                if let Ok(msg) = verification {
                    make_request(&msg, false);
                } else {
                    println!("Transaction NOT Sent.");
                }
            }
            "BAL" => {
                print!("Uname: ");
                let mut uname = String::new(); 
                std::io::stdout().flush().unwrap();
                io::stdin().read_line(&mut uname)?;

                let request = format!("{:48}", uname.trim());
                let verification = user_verify_nonaction(b"BAL", &request);

                if let Ok(msg) = verification {
                    make_request(&msg, true);
                } else {
                    println!("Balance request NOT sent.");
                }
            },
            "OWE" => {
                print!("<Uname> Owes (* for everyone): ");
                let mut owes = String::new(); 
                std::io::stdout().flush().unwrap();
                io::stdin().read_line(&mut owes)?;
            
                print!("To <Uname> (* for everyone): ");
                let mut to = String::new(); 
                std::io::stdout().flush().unwrap();
                io::stdin().read_line(&mut to)?;

                let request = format!("{:48}", format!("{} {}", owes.trim(), to.trim()));
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
        print!("Would You like to make another request? [y/N]: ");
        let mut approved = String::new();
        std::io::stdout().flush().unwrap();
        io::stdin().read_line(&mut approved)?;
        let approved = approved.trim();
    
        approved.to_uppercase() == "Y"
    } {}

    Ok(())
}

fn ecb_rsa_encrypt(pk: RsaPublicKey, msg: &[u8]) -> Result<Vec<u8>, ()> {
    let blocks = {
        let (label, remainder) = msg.split_at(3);
        // n = factor of 8, 309, 50, 308; if we get the numbers to 8 304 48 304 n can be 24
        // to get it there   ^   jc   ^ remove spaces
        //                  308  --  306
        //                            ^ correct nonconforming 16 name cap to 15
        //                  308  --  304
        //          f(n) = der_size + n  g(n) = key_size + 2n + money_digit_cap + ts_size 
        //          f(n) = 294 + n  g(n) = 256 + 2n + money_digit_cap + 8
        //          f(n) = 294 + n  g(n) = 264 + 2n + money_digit_cap
        //          
        //          money_digit_cap must be 12 and n must be 18
        //          or for now there must be 2 units of whitespace money_digit_cap must be 10 and n = 18
        let msg_chunks = remainder.chunks_exact(24);
        let mut msg_blocks_deque = VecDeque::from_iter(msg_chunks.into_iter());
        msg_blocks_deque.push_front(label);
        msg_blocks_deque
    };

    let encrypted_msg: Vec<u8> = blocks.into_iter().map(|block| {
        pk.encrypt(&mut OsRng, PaddingScheme::new_oaep::<sha2::Sha256>(), block).unwrap()
    }).flatten().collect(); // LIB FIX: PaddingScheme should implement Copy

    Ok(encrypted_msg)
}

/// Make request from server.
fn make_request(msg: &[u8], await_data: bool) {
    match TcpStream::connect(SERVER) {
        Ok(mut stream) => {
            println!("Successfully connected");

            println!("Encrypting Packet ...");

            let mut key_buf = [0_u8; 120];
            stream.read_exact(&mut key_buf).unwrap();
            let srv_pk = RsaPublicKey::from_public_key_der(&key_buf).unwrap();
            
            let encrypted_msg = ecb_rsa_encrypt(srv_pk, msg).unwrap();
            stream.write(&encrypted_msg[..]).unwrap();

            println!("Sent request, awaiting confirmation ...");

            let mut confirmation = [0_u8; 3];
            match stream.read_exact(&mut confirmation) {
                Ok(_) => {
                    match (&confirmation, await_data) {
                        (b"OK ", true) => {
                            println!("Received Confirmation, awaiting data ...");
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
                        (b"OK ", false) => {
                            println!("Confirmation Received. Success");
                        },

                        // Errors
                        (b"E00", _) => { println!("Error 00: The server had issues accessing some resources."); },
                        (b"E01", _) => { unreachable!("Error 01: Bad request type. This should be unreachable because user input is filtered."); },
                        (b"E02", _) => { println!("Error 02: Bad timestamp. Your transaction took too long or was sent within a second of your last transaction."); },
                        (b"E03", _) => { println!("Error 03: Rejected badly signed transaction."); },
                        (b"E04", _) => { println!("Error 04: Your user is not registered with the server. Please create an account with the signup binary or check the username of the last transaction."); }, 
                        (b"E05", _) => { println!("Error 05: The user you tried to send to does not exist."); },
                        // E06 is an error for the signup binary

                        (other, _) => { print!("Unexpected response: {}", std::str::from_utf8(other).unwrap()); },
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
