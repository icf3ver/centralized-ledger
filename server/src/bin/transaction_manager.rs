use std::fs::{self, File, OpenOptions};
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Error, ErrorKind, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use rsa::pkcs8::{FromPublicKey, ToPublicKey};
use rsa::{PaddingScheme, PublicKey, RsaPublicKey, RsaPrivateKey};
use serde::{Serialize, Deserialize};
use sha2::Digest;
use log::{info, warn, error};
use rand::rngs::OsRng;

// const REQUESTS: [&'static str; 3] = ["SEN", "BAL", "OWE", "ACC"];

const LEDGER: &'static str = "./server/ledger.txt";
const USR_DIR: &'static str = "./server/usr_dir/";

#[derive(Clone, Copy)]
enum SrvError {
    SystemError = /*E0*/0, // Err when trying to access resources
    BadRequest, // Request does not exist
    BadTimestamp, // Timestamp is off by over 10 seconds or 
    BadSignature, // Signature is invalid
    UnknownSender, // The sender does not exist as a user
    UnknownDestination, // The recipient does not exist as a user
    UserExists, // Attempted creation of user that already exists
}

impl SrvError {
    fn err_code(&self) -> String {
        format!("E{:0>2}", *self as u32)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct User<'a>{
    uname: &'a str,
    public_key: RsaPublicKey,
}

fn check_timestamp(ts: u64, user: &str) -> bool {
    // If it is unique and it is valid then for all I care it is fine.
    // Checking for uniqueness
    let delta = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 - ts as i64;
    !std::str::from_utf8(&fs::read(LEDGER).unwrap()[..]).unwrap().split('\n').any(|line| {
        let mut line_parts = line.split(' ');
        line != "" && line_parts.next().unwrap() == ts.to_string() && line_parts.next().unwrap() == user
    }) && delta <= 10 // && delta >= 0 // = && true because delta is an integer
}

fn handle_transaction (transaction_buf: [u8; 312], mut stream: TcpStream) {
    let hash: &[u8] = &sha2::Sha512::digest(&transaction_buf[..56])[..];
    let signature = &transaction_buf[56..];
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_512));

    let msg = std::str::from_utf8(&transaction_buf[8..56]).unwrap();

    // Sender
    let mut msg_pts_tmp = msg.split_whitespace();
    let sender = msg_pts_tmp.next().unwrap().trim();
    let recipient = msg_pts_tmp.next().unwrap().trim();
    drop(msg_pts_tmp);

    // Time Stamp
    let mut raw_ts: [u8; 8] = [0; 8];
    raw_ts.copy_from_slice(&transaction_buf[..8]);
    let ts = u64::from_be_bytes(raw_ts);

    // Check Timestamp
    if !check_timestamp(ts, sender) {
        warn!("Bad timestamp client {} : sent {} at {}s", stream.peer_addr().unwrap(), msg.trim(), ts);
        stream.write(SrvError::BadTimestamp.err_code().as_bytes()).unwrap();
        return ();
    }

    // Check Sender
    let user_raw = match fs::read(USR_DIR.to_owned() + sender) {
        Ok(raw) => raw,
        Err(_e) => {
            warn!("Unknown user {} at {} tried: {}", sender, stream.peer_addr().unwrap(), msg.trim());
            stream.write(SrvError::UnknownSender.err_code().as_bytes()).unwrap();
            return ();
        }
    };
    let user: User = bincode::deserialize(&user_raw[..]).unwrap();

    // Check Recipient
    #[allow(unused_variables)] // Compiler Bug
    let error = Error::from(ErrorKind::NotFound);
    #[allow(unused_variables)]
    if let Err(error) = fs::read(USR_DIR.to_owned() + recipient) {
        warn!("User {} tried to send to unknown user {}: {}", sender, stream.peer_addr().unwrap(), msg.trim());
        stream.write(SrvError::UnknownDestination.err_code().as_bytes()).unwrap(); // TODO remap error codes
        return ();
    };
    
    // Check Signature
    let public_key = user.public_key;
    if let Err(_) = public_key.verify(padding, &hash, signature) {
        error!("Badly signed transaction by {} : {}", stream.peer_addr().unwrap(), msg.trim());
        stream.write(SrvError::BadSignature.err_code().as_bytes()).unwrap();
        return ();
    }

    // Write To Ledger
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(LEDGER)
        .unwrap();

    // Store signature as hex (for now)
    let mut hex_signature = String::new();
    for byte in signature {
        hex_signature.push_str(format!("{:02x}", byte).as_str());
    }

    if let Err(e) = writeln!(file, "{} {}{}", ts, msg, hex_signature) {
        error!("Couldn't write to ledger: {}", e);
        stream.write(SrvError::SystemError.err_code().as_bytes()).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();
        return ();
    }
    
    info!("Transaction by {} : {}", stream.peer_addr().unwrap(), msg.trim());
    stream.write(b"OK ").unwrap();
}

fn handle_new_account_request (account_buf: [u8; 312], mut stream: TcpStream) {
    let (uname, public_key) = (
        std::str::from_utf8(&account_buf[..18]).unwrap().trim().to_owned(), 
        RsaPublicKey::from_public_key_der(&account_buf[18..]).unwrap()
    );
    let file_name = format!("{}{}", USR_DIR, uname);
    let file_path = std::path::Path::new(&file_name);
    if file_path.exists() {
        warn!("Attempted reuse of uname {} by {}", uname, stream.peer_addr().unwrap());
        stream.write(SrvError::UserExists.err_code().as_bytes()).unwrap();
    } else {
        let mut file = File::create(file_path).unwrap();
        file.write_all(&bincode::serialize(&User{ uname: &uname, public_key }).unwrap()[..]).unwrap();
        info!("New user {}", uname);
        stream.write(b"OK ").unwrap();
    }
}

fn handle_request(request: &[u8], other_buf: [u8; 48], mut stream: TcpStream) {
    /// how much first send to other. Default (None) is everyone.
    fn get_owe (first: Option<&str>, other: Option<&str>) -> u64 {
        let mut result = 0;
        std::str::from_utf8(&fs::read(LEDGER).unwrap()[..]).unwrap().split('\n').for_each(|line| {
            if line != "" {
                let mut line_parts = line.split_whitespace();
                line_parts.next().unwrap(); // timestamp
                let first_ledger = line_parts.next().unwrap();
                let other_ledger = line_parts.next().unwrap();
                if (first.is_none() || first_ledger == first.unwrap()) 
                        && (other.is_none() || other_ledger == other.unwrap()) {
                    result += line_parts.next().unwrap().parse::<u64>().unwrap(); 
                    // TODO prevent overflow and set up decimal places without floating point numbers
                }
            }
        });
        result
    }

    /// how much you are owed. What you have been sent.
    #[inline]
    fn get_all_owed (uname: &str) -> u64 {
        get_owe(None, Some(uname))
    }

    /// how much you owe. What you have sent.
    #[inline]
    fn get_all_owes (uname: &str) -> u64 {
        get_owe(Some(uname), None)
    }

    let msg = std::str::from_utf8(&other_buf[..]).unwrap();
    let mut msg_components = msg.split_whitespace();
    let first_target = msg_components.next().unwrap_or(""); // Caught by request.is_none()
    let other_target = msg_components.next();

    match request {
        b"BAL" if other_target.is_none() => { // only single arg request
            let sum = get_all_owed(first_target) as i64 - get_all_owes(first_target) as i64;
            info!("Balance request from {} : {}", stream.peer_addr().unwrap(), msg.trim());
            stream.write(&[b"OK ", &sum.to_be_bytes()[..]].concat()[..]).unwrap();
        },
        b"OWE" if other_target.is_some() => {
            let other_target = other_target.unwrap();
            let result = match (first_target, other_target) { // no context is a good idea
                (first, "*") => get_all_owes(first),
                ("*", other) => get_all_owed(other),
                (first, other) => get_owe(Some(first), Some(other))
            } as i64;
            info!("Debt request from {} : {}", stream.peer_addr().unwrap(), msg.trim());
            stream.write(&[b"OK ", &result.to_be_bytes()[..]].concat()[..]).unwrap();
        },
        _ => {
            warn!("Bad request from {} : {}", stream.peer_addr().unwrap(), msg.trim());
            stream.write(SrvError::BadRequest.err_code().as_bytes()).unwrap();
        }
    }
}

fn ecs_rsa_decrypt<const I: usize, const O: usize>(sk: RsaPrivateKey, encrypted_buf: [u8; I]) -> [u8; O] {
    let mut arr: [u8; O] = [0_u8; O];
    arr.copy_from_slice(&encrypted_buf.chunks_exact(90).map(|block| {
        sk.decrypt(PaddingScheme::new_oaep::<sha2::Sha256>(), block).unwrap()
    }).flatten().collect::<Vec<u8>>()[..]);
    arr
}

fn handle_client(mut stream: TcpStream) {
    // encrypting communication                                    
    let bit_k = 720;
    // mLen <= k - 2hLen - 2
    // hLen = 256/8 bytes = 32 bytes
    // note the 2 more bytes are not usable
    // k must therefore be bigger than 66 bytes every byte bigger means one character more
    // max msg size is 469 bytes
    // so k = 66 + 469 = 535 bytes or exactly 4280 bits
    // This takes too long so I will use ECB first and later move to CBC
    // block sizes will be 24 bytes
    // therefore key size = 90 bytes or 720 bits
    let sk = RsaPrivateKey::new(&mut OsRng, bit_k).expect("failed to generate a key");
    let pk = sk.to_public_key();
    let pk_der = RsaPublicKey::to_public_key_der(&pk).unwrap();
    let pk_der_bytes = pk_der.as_ref();
    stream.write_all(pk_der_bytes).unwrap();

    let mut encrypted_request = [0_u8; 90];
    if let Ok(()) = stream.read_exact(&mut encrypted_request) {
        let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
        match &sk.decrypt(padding, &encrypted_request[..]).unwrap()[..] {
            b"SEN" => {
                let mut encrypted_transaction_buf = [0_u8; 1170];
                if let Ok(()) = stream.read_exact(&mut encrypted_transaction_buf){
                    let transaction_buf: [u8; 312] = ecs_rsa_decrypt(sk, encrypted_transaction_buf);
                    handle_transaction(transaction_buf, stream);
                } else {
                    warn!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
                    stream.shutdown(Shutdown::Both).unwrap();
                }
            },
            b"ACC" => {
                let mut encrypted_account_buf = [0_u8; 1170];
                if let Ok(()) = stream.read_exact(&mut encrypted_account_buf){
                    let account_buf: [u8; 312] = ecs_rsa_decrypt(sk, encrypted_account_buf);
                    handle_new_account_request(account_buf, stream);
                } else {
                    warn!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
                    stream.shutdown(Shutdown::Both).unwrap();
                }
            },
            request => {
                let mut encrypted_other_buf = [0_u8; 180];
                if let Ok(()) = stream.read_exact(&mut encrypted_other_buf) {
                    let other_buf: [u8; 48] = ecs_rsa_decrypt(sk, encrypted_other_buf);
                    handle_request(request, other_buf, stream);
                } else {
                    warn!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
                    stream.shutdown(Shutdown::Both).unwrap();
                }
            }
        }
    } else {
        warn!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
        stream.shutdown(Shutdown::Both).unwrap();
    }
}

fn main() {
    env_logger::init();
    let listener = TcpListener::bind("0.0.0.0:5555").unwrap();
    // accept connections and process them, spawning a new thread for each one
    info!(target: "centralized_ledger_events", "Server listening on port 5555");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("Connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| { 
                    handle_client(stream)
                });
            },
            Err(e) => {
                warn!("A Connection Failed: {}", e);
            }
        }
    }
    drop(listener);
}