extern crate bao;
extern crate hex;
#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate clap;

use std::io;
use std::io::prelude::*;
use std::error::Error;
use std::fs::OpenOptions;
use hex::{FromHex, ToHex};
use clap::{App, Arg, SubCommand, ArgMatches};

macro_rules! exit {
    ($fmt:expr) => {{
        eprintln!($fmt);
        use std::process::exit;
        exit(1);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        use std::process::exit;
        exit(1);
    }};
}

fn encode(args: &ArgMatches) -> io::Result<()> {
    let stdin = io::stdin();
    match (args.value_of("output"), args.is_present("memory")) {
        (None, false) => exit!("must specify either an output file or --memory"),
        (Some(_), true) => exit!("cannot use both an output file and --memory"),
        (None, true) => {
            let mut output = io::Cursor::new(Vec::<u8>::new());
            {
                let mut writer = bao::io::Writer::new(&mut output);
                io::copy(&mut stdin.lock(), &mut writer)?;
                writer.finish().unwrap();
            }
            io::stdout().write_all(output.get_ref()).unwrap();
        }
        (Some(file), false) => {
            let mut writer = bao::io::Writer::new(OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(file)?);
            io::copy(&mut stdin.lock(), &mut writer)?;
            let hash = writer.finish().unwrap();
            println!("{}", hash.to_hex());
        }
    }
    Ok(())
}

fn decode(args: &ArgMatches) -> io::Result<()> {
    let hash_vec = Vec::from_hex(args.value_of("hash").unwrap()).expect("valid hex");
    if hash_vec.len() != bao::DIGEST_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "hash must be {} bytes, got {}",
                bao::DIGEST_SIZE,
                hash_vec.len()
            ),
        ));
    };
    let hash_array = *array_ref!(&hash_vec, 0, bao::DIGEST_SIZE);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = bao::io::Reader::new(stdin.lock(), &hash_array);
    io::copy(&mut reader, &mut stdout.lock()).unwrap();
    Ok(())
}

fn main() {
    let app = App::new("bao")
        .version(crate_version!())
        .subcommand(
            SubCommand::with_name("encode")
                .arg(Arg::with_name("output").help(
                    "the file to write the tree to",
                ))
                .arg(Arg::with_name("memory").long("--memory").help(
                    "encode in memory and write to stdout afterwards",
                )),
        )
        .subcommand(SubCommand::with_name("decode").arg(
            Arg::with_name("hash").required(true).help(
                "the hash given by `encode`",
            ),
        ));
    let matches = app.get_matches();
    let ret = match matches.subcommand() {
        ("encode", Some(args)) => encode(args),
        ("decode", Some(args)) => decode(args),
        rest => {
            exit!("other args: {:?}", rest);
        }
    };
    if let Err(e) = ret {
        exit!("{}", e.description());
    }
}
