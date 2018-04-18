#[macro_use]
extern crate arrayref;
extern crate bao;
extern crate docopt;
extern crate hex;
#[macro_use]
extern crate serde_derive;

use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;

fn encode(args: &Args) -> io::Result<()> {
    let stdin = io::stdin();
    if args.flag_memory {
        let mut output = io::Cursor::new(Vec::<u8>::new());
        {
            let mut writer = bao::io::Writer::new(&mut output);
            io::copy(&mut stdin.lock(), &mut writer)?;
            writer.finish()?;
        }
        io::stdout().write_all(output.get_ref())?;
    } else {
        let mut writer = bao::io::Writer::new(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&args.arg_output)?);
        if args.arg_input == "-" {
            io::copy(&mut stdin.lock(), &mut writer)?;
        } else {
            let mut infile = File::open(&args.arg_input)?;
            io::copy(&mut infile, &mut writer)?;
        }
        let hash = writer.finish()?;
        println!("{}", hex::encode(hash));
    }
    Ok(())
}

fn decode(args: &Args) -> io::Result<()> {
    let mut stdin = io::stdin();
    let stdout = io::stdout();
    if args.flag_any {
        // TODO: Expose an "any" constructor for the decoder.
        let mut header_bytes = [0; 8];
        stdin.read_exact(&mut header_bytes).unwrap();
        // TODO: THIS IS NOT CORRECT
        let header_hash = bao::hash::hash(&header_bytes);
        let chained_reader = io::Cursor::new(&header_bytes[..]).chain(stdin.lock());
        let mut reader = bao::io::Reader::new(chained_reader, &header_hash);
        io::copy(&mut reader, &mut stdout.lock())?;
    } else {
        let hash_vec = hex::decode(&args.flag_hash).expect("valid hex");
        if hash_vec.len() != bao::hash::DIGEST_SIZE {
            panic!(
                "hash must be {} bytes, got {}",
                bao::hash::DIGEST_SIZE,
                hash_vec.len()
            );
        };
        let hash_array = *array_ref!(&hash_vec, 0, bao::hash::DIGEST_SIZE);
        let mut reader = bao::io::Reader::new(stdin.lock(), &hash_array);
        io::copy(&mut reader, &mut stdout.lock()).unwrap();
    }
    Ok(())
}

fn hash(_args: &Args) -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut state = bao::hash::StateParallel::new();
    let mut read_buffer = [0; 4096];
    loop {
        let n = stdin_lock.read(&mut read_buffer)?;
        if n == 0 {
            break; // EOF
        }
        state.update(&read_buffer[..n]);
    }
    let hash = state.finalize();
    println!("{}", hex::encode(hash));
    Ok(())
}

const USAGE: &str = "
Usage: bao encode (<input> <output> | --memory)
       bao decode (--hash=<hash> | --any)
       bao hash
";

#[derive(Debug, Deserialize)]
struct Args {
    arg_input: String,
    arg_output: String,
    cmd_decode: bool,
    cmd_encode: bool,
    cmd_hash: bool,
    flag_any: bool,
    flag_hash: String,
    flag_memory: bool,
}

fn main() {
    let args: Args = docopt::Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    // TODO: Error reporting.
    if args.cmd_encode {
        encode(&args).unwrap();
    } else if args.cmd_decode {
        decode(&args).unwrap();
    } else if args.cmd_hash {
        hash(&args).unwrap();
    }
}
