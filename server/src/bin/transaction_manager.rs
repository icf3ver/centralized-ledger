use std::fs::{self, OpenOptions};
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use serde::{Serialize, Deserialize};
use sha2::Digest;

// const REQUESTS: [&'static str; 3] = ["SEN", "BAL", "OWE"];

const LEDGER: &'static str = "./server/ledger.txt";
const USR_DIR: &'static str = "./server/usr_dir/";

#[derive(Debug, Serialize, Deserialize)]
struct User<'a>{
    uname: &'a str,
    public_key: RsaPublicKey,
}

fn handle_transaction (transaction_buf: [u8; 300], mut stream: TcpStream) {
    let msg = std::str::from_utf8(&transaction_buf[..44]).unwrap();
    let hash: &[u8] = &sha2::Sha512::digest(msg.as_bytes())[..];
    let signature = &transaction_buf[44..];
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_512));
    // Sender
    let sender = msg.split(' ').next().unwrap().trim();
    // Check Sender
    if let Ok(user_raw) = fs::read(USR_DIR.to_owned() + sender) {
        let user: User = bincode::deserialize(&user_raw[..]).unwrap();
        let public_key = user.public_key;
        // Check Signature
        if let Ok(()) = public_key.verify(padding, &hash, signature){
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(LEDGER) // todo sync
                .unwrap();

            if let Err(e) = writeln!(file, "{}", msg) {
                eprintln!("Couldn't write to file: {}", e);
            }
            println!("Transaction by {} : {}", stream.peer_addr().unwrap(), msg.trim());
            stream.write(b"GO").unwrap();
        } else {
            println!("Bad transaction by {} : {}", stream.peer_addr().unwrap(), msg.trim());
            stream.write(b"NO").unwrap();
        }
    } else {
        println!("Unknown user {} at {} tried: {}", sender, stream.peer_addr().unwrap(), msg.trim());
        stream.write(b"NO").unwrap();
    }
}

fn handle_request(request: [u8; 3], other_buf: [u8; 50], mut stream: TcpStream) {
    /// how much first send to other. Default (None) is everyone.
    fn get_owe (first: Option<&str>, other: Option<&str>) -> u64 {
        let mut result = 0;
        std::str::from_utf8(&fs::read(LEDGER).unwrap()[..]).unwrap().split('\n').for_each(|line| {
            if line != "" {
                let mut line_parts = line.split(' ');
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

    if &request == b"BAL" && other_target.is_none() { // only single arg request
        let sum = get_all_owed(first_target) as i64 - get_all_owes(first_target) as i64;
        println!("Balance request from {} : {}", stream.peer_addr().unwrap(), msg.trim());
        stream.write(&[b"GO", &sum.to_be_bytes()[..]].concat()[..]).unwrap();
    } else if &request == b"OWE" && other_target.is_some() {
        let other_target = other_target.unwrap();
        let result = match (first_target, other_target) { // no context is a good idea
            (first, "*") => get_all_owed(first),
            ("*", other) => get_all_owes(other),
            (first, other) => get_owe(Some(first), Some(other))
        } as i64;
        println!("Debt request from {} : {}", stream.peer_addr().unwrap(), msg.trim());
        stream.write(&[b"GO", &result.to_be_bytes()[..]].concat()[..]).unwrap();
    } else {
        println!("Bad request from {} : {}", stream.peer_addr().unwrap(), msg.trim());
        stream.write("NO".as_bytes()).unwrap();
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut request = [0_u8; 3];
    if let Ok(()) = stream.read_exact(&mut request) {
        if &request == b"SEN" {
            let mut transaction_buf = [0_u8; 300];
            if let Ok(()) = stream.read_exact(&mut transaction_buf){
                handle_transaction(transaction_buf, stream);
            } else {
                println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
                stream.shutdown(Shutdown::Both).unwrap();
            }
        } else {
            let mut other_buf = [0_u8; 50];
            if let Ok(()) = stream.read_exact(&mut other_buf) {
                handle_request(request, other_buf, stream);
            } else {
                println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
                stream.shutdown(Shutdown::Both).unwrap();
            }
        } 
    } else {
        println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
        stream.shutdown(Shutdown::Both).unwrap();
    }
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5555").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 5555");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("Connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    // connection succeeded
                    handle_client(stream)
                });
            }
            Err(e) => {
                // connection failed
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}