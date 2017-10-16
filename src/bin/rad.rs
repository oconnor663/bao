extern crate rad;
extern crate hex;
#[macro_use]
extern crate arrayref;

use std::io;
use std::error::Error;
use std::fs::OpenOptions;
use hex::{FromHex, ToHex};

fn encode(output: &str) -> io::Result<()> {
    let mut writer = rad::io::Writer::new(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output)?);
    let stdin = io::stdin();
    io::copy(&mut stdin.lock(), &mut writer)?;
    let hash = writer.finish().unwrap();
    println!("{}", hash.to_hex());
    Ok(())
}

fn decode(hash: &str) -> io::Result<()> {
    let hash_vec = Vec::from_hex(hash).expect("valid hex");
    if hash_vec.len() != rad::DIGEST_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "hash must be {} bytes, got {}",
                rad::DIGEST_SIZE,
                hash_vec.len()
            ),
        ));
    };
    let hash_array = *array_ref!(&hash_vec, 0, rad::DIGEST_SIZE);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = rad::io::Reader::new(stdin.lock(), &hash_array);
    io::copy(&mut reader, &mut stdout.lock()).unwrap();
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("command missing");
        std::process::exit(1);
    }
    if args.len() < 3 {
        eprintln!("argument missing");
        std::process::exit(1);
    }
    let ret = match args[1].as_str() {
        "encode" => encode(&args[2]),
        "decode" => decode(&args[2]),
        command => {
            eprintln!("unknown command: {}", command);
            std::process::exit(1);
        }
    };
    if let Err(e) = ret {
        eprintln!("{}", e.description());
        std::process::exit(1);
    }
}
