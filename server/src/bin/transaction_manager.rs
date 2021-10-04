use std::fs::{self, OpenOptions};
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use serde::{Serialize, Deserialize};
use sha2::Digest;

const LEDGER: &'static str = "./server/ledger.txt";
const USR_DIR: &'static str = "./server/usr_dir/";

#[derive(Debug, Serialize, Deserialize)]
struct User<'a>{
    uname: &'a str,
    public_key: RsaPublicKey,
}

fn handle_client(mut stream: TcpStream) {
    let mut transaction_buf = [0_u8; 300];
    if let Ok(()) = stream.read_exact(&mut transaction_buf) {
        let msg = std::str::from_utf8(&transaction_buf[..44]).unwrap();
        let hash: &[u8] = &sha2::Sha512::digest(msg.as_bytes())[..];
        let signature = &transaction_buf[44..];
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_512));
        // Sender
        let sender = msg.split(' ').next().unwrap().trim();
        let user = fs::read(USR_DIR.to_owned() + sender).unwrap();
        let user: User = bincode::deserialize(&user[..]).unwrap();
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
            stream.write(b"GO").unwrap();
        } else {
            stream.write(b"NO").unwrap();
        }
    } else {
        println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
        stream.shutdown(Shutdown::Both).unwrap();
    }
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3333");
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