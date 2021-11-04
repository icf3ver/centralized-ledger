use std::net::{TcpStream};
use std::io::{self, Read, Write};
use std::str::from_utf8;

const SERVER: &'static str = "localhost:5555";

fn main() -> Result<(), io::Error> {
    let mut request = String::new();
    while {
        println!("Request Type:");
        let mut request_type = String::new(); 
        io::stdin().read_line(&mut &mut request_type)?;
        request_type = request_type.to_uppercase();
        
        match request_type.as_str().trim() {
            "BAL" => {
                println!("Uname :");
                let mut uname = String::new(); 
                io::stdin().read_line(&mut uname)?;

                request = format!("{:53}", format!("BAL{}", uname.trim()));
                false
            },
            "OWE" => {
                println!("<Uname> Owes (* for everyone):");
                let mut owes = String::new(); 
                io::stdin().read_line(&mut owes)?;
            
                println!("To <Uname> (* for everyone):");
                let mut to = String::new(); 
                io::stdin().read_line(&mut to)?;

                request = format!("{:53}", format!("OWE{} {}", owes.trim(), to.trim()));
                false
            },
            other => {
                eprintln!("{} is not a valid request", other);

                println!("Would You like to make another request? [Y/n]: ");

                let mut approved = String::new();
                io::stdin().read_line(&mut approved)?;
                let approved = approved.trim();

                if approved.to_uppercase() == "N" {
                    panic!("Exit")
                }
                true
            }
        }
    } {}

    println!("Please verify the request:\n{:50}", request);
    println!("[y/N]:");
    let mut approved = String::new();
    io::stdin().read_line(&mut approved)?;
    let approved = approved.trim();

    if approved.to_uppercase() == "Y" {
        make_request(&request);
    }
    Ok(())
}


fn make_request(msg: &str) {
    match TcpStream::connect(SERVER) {
        Ok(mut stream) => {
            println!("Successfully connected");

            // send request
            let msg: &[u8] = msg.as_bytes();
            println!("{:?}", msg.len());
            stream.write(msg).unwrap();

            println!("Sent request, awaiting confirmation...");

            let mut confirmation = [0_u8; 2];
            match stream.read_exact(&mut confirmation) {
                Ok(_) => {
                    if &confirmation[..2] == b"GO" {
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
                    } else if &confirmation[..2] == b"NO" {
                        println!("Failure");
                    } else {
                        let text = from_utf8(&confirmation).unwrap();
                        println!("Unexpected reply: {}", text);
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
