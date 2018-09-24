#[macro_use]
extern crate arrayref;
extern crate bao;
extern crate docopt;
extern crate failure;
extern crate hex;
extern crate os_pipe;
#[macro_use]
extern crate serde_derive;
extern crate memmap;

use failure::{err_msg, Error};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::iter;
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

// Note that docopt.rs currently has a bug related to commands wrapped over multiple lines, so
// don't wrap them. https://github.com/docopt/docopt.rs/issues/244
const USAGE: &str = "
Usage: bao hash [<input>] [<inputs>... | --encoded | --outboard=<file>]
       bao encode <input> (<output> | --outboard=<file>)
       bao decode <hash> [<input>] [<output>] [--outboard=<file>] [--start=<offset>] [--count=<count>]
       bao slice <start> <count> [<input>] [<output>] [--outboard=<file>]
       bao decode-slice <hash> <start> <count> [<input>] [<output>]
       bao (--help | --version)
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_decode: bool,
    cmd_encode: bool,
    cmd_hash: bool,
    cmd_slice: bool,
    cmd_decode_slice: bool,
    arg_input: Option<PathBuf>,
    arg_inputs: Vec<PathBuf>,
    arg_output: Option<PathBuf>,
    arg_hash: String,
    arg_start: u64,
    arg_count: u64,
    flag_count: Option<u64>,
    flag_encoded: bool,
    flag_help: bool,
    flag_outboard: Option<PathBuf>,
    flag_start: Option<u64>,
    flag_version: bool,
}

fn main() -> Result<(), Error> {
    let args: Args = docopt::Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_help {
        print!("{}", USAGE);
    } else if args.flag_version {
        println!("{}", VERSION);
    } else if args.cmd_hash {
        hash(&args)?;
    } else if args.cmd_encode {
        encode(&args)?;
    } else if args.cmd_decode {
        decode(&args)?;
    } else if args.cmd_slice {
        slice(&args)?;
    } else if args.cmd_decode_slice {
        decode_slice(&args)?;
    } else {
        unreachable!();
    }

    Ok(())
}

fn hash_one(maybe_path: &Option<PathBuf>, args: &Args) -> Result<bao::hash::Hash, Error> {
    let mut in_file = open_input(maybe_path)?;
    Ok(if args.flag_outboard.is_some() {
        let mut outboard_file = open_input(&args.flag_outboard)?;
        bao::decode::hash_from_outboard_encoded(&mut in_file, &mut outboard_file)?
    } else if args.flag_encoded {
        bao::decode::hash_from_encoded(&mut in_file)?
    } else if let Some(map) = maybe_memmap_input(&in_file)? {
        bao::hash::hash(&map)
    } else {
        let mut writer = bao::hash::Writer::new();
        io::copy(&mut in_file, &mut writer)?;
        writer.finish()
    })
}

fn hash(args: &Args) -> Result<(), Error> {
    if !args.arg_inputs.is_empty() {
        let mut did_error = false;
        let all_inputs = iter::once(args.arg_input.as_ref().unwrap()).chain(args.arg_inputs.iter());
        for input in all_inputs {
            let input_str = input.to_string_lossy();
            // As with b2sum or sha1sum, the multi-arg hash loop prints errors and keeps going.
            // This is more convenient for the user in cases like `bao hash *`, where it's common
            // that some of the inputs will error on read e.g. because they're directories.
            match hash_one(&Some(input.clone()), args) {
                Ok(hash) => {
                    println!("{}  {}", hex::encode(hash), input_str);
                }
                Err(e) => {
                    did_error = true;
                    println!("bao: {}: {}", input_str, e);
                }
            }
        }
        if did_error {
            std::process::exit(1);
        }
    } else {
        let hash = hash_one(&args.arg_input, &args)?;
        println!("{}", hex::encode(hash));
    }
    Ok(())
}

fn encode(args: &Args) -> Result<(), Error> {
    let mut in_file = open_input(&args.arg_input)?;
    let out_maybe_path = if args.flag_outboard.is_some() {
        &args.flag_outboard
    } else {
        &args.arg_output
    };
    // The output will always require read permissions, either to flip the tree or to mmap it, and
    // stdout practically never has the right permissions. Return an error if the output is "-".
    if path_if_some_and_not_dash(out_maybe_path).is_none() {
        return Err(err_msg(format!("encode output cannot be stdout")));
    }
    let out_file = open_output(out_maybe_path)?;
    if let Some(in_map) = maybe_memmap_input(&in_file)? {
        let target_len = if args.flag_outboard.is_some() {
            bao::encode::outboard_size(in_map.len() as u64)
        } else {
            bao::encode::encoded_size(in_map.len() as u64)
        };
        if let Some(mut out_map) = maybe_memmap_output(&out_file, target_len)? {
            if args.flag_outboard.is_some() {
                bao::encode::encode_outboard(&in_map, &mut out_map);
            } else {
                bao::encode::encode(&in_map, &mut out_map);
            }
            return Ok(());
        }
    }
    // If one or both of the files weren't mappable, fall back to the writer. First check that we
    // have an actual file and not a pipe, because the writer requires seek.
    confirm_real_file(&out_file, "encode output")?;
    let mut writer;
    if args.flag_outboard.is_some() {
        writer = bao::encode::Writer::new_outboard(out_file);
    } else {
        writer = bao::encode::Writer::new(out_file);
    };
    io::copy(&mut in_file, &mut writer)?;
    writer.finish()?;
    Ok(())
}

fn decode(args: &Args) -> Result<(), Error> {
    let in_file = open_input(&args.arg_input)?;
    let mut out_file = open_output(&args.arg_output)?;
    let hash = parse_hash(args)?;
    // Don't mmap stdout. It practically never has the read permissions required for mapping.
    let is_stdout = path_if_some_and_not_dash(&args.arg_output).is_none();
    let special_options =
        args.flag_start.is_some() || args.flag_count.is_some() || args.flag_outboard.is_some();
    // If we're not seeking or outboard or stdout, try to memmap the files.
    if !special_options && !is_stdout {
        if let Some(in_map) = maybe_memmap_input(&in_file)? {
            let content_len = bao::decode::parse_and_check_content_len(&in_map)?;
            if let Some(mut out_map) = maybe_memmap_output(&out_file, content_len as u128)? {
                bao::decode::decode(&in_map, &mut out_map, &hash)?;
                return Ok(());
            }
        }
    }
    // If the files weren't mappable, or if we're seeking or outboard, fall back to the reader.
    let outboard_file;
    let mut reader;
    if args.flag_outboard.is_some() {
        outboard_file = open_input(&args.flag_outboard)?;
        if args.flag_start.is_some() {
            confirm_real_file(&outboard_file, "when seeking, decode input")?;
        }
        reader = bao::decode::Reader::new_outboard(&in_file, &outboard_file, &hash);
    } else {
        reader = bao::decode::Reader::new(&in_file, &hash);
    }
    if let Some(offset) = args.flag_start {
        confirm_real_file(&in_file, "when seeking, decode input")?;
        reader.seek(io::SeekFrom::Start(offset))?;
    }
    if let Some(count) = args.flag_count {
        let mut taker = reader.take(count);
        allow_broken_pipe(io::copy(&mut taker, &mut out_file))?;
    } else {
        allow_broken_pipe(io::copy(&mut reader, &mut out_file))?;
    }
    Ok(())
}

fn slice(args: &Args) -> Result<(), Error> {
    let in_file = open_input(&args.arg_input)?;
    let mut out_file = open_output(&args.arg_output)?;
    // Slice extraction requires seek.
    confirm_real_file(&in_file, "slicing input")?;
    let outboard_file;
    let mut extractor;
    if args.flag_outboard.is_some() {
        outboard_file = open_input(&args.flag_outboard)?;
        confirm_real_file(&outboard_file, "slicing input")?;
        extractor = bao::encode::SliceExtractor::new_outboard(
            in_file,
            outboard_file,
            args.arg_start,
            args.arg_count,
        );
    } else {
        extractor = bao::encode::SliceExtractor::new(in_file, args.arg_start, args.arg_count);
    }
    io::copy(&mut extractor, &mut out_file)?;
    Ok(())
}

fn decode_slice(args: &Args) -> Result<(), Error> {
    let in_file = open_input(&args.arg_input)?;
    let mut out_file = open_output(&args.arg_output)?;
    let hash = parse_hash(&args)?;
    let mut reader = bao::decode::SliceReader::new(in_file, &hash, args.arg_start, args.arg_count);
    allow_broken_pipe(io::copy(&mut reader, &mut out_file))?;
    Ok(())
}

fn path_if_some_and_not_dash(maybe_path: &Option<PathBuf>) -> Option<&Path> {
    if let Some(ref path) = maybe_path {
        if path == Path::new("-") {
            None
        } else {
            Some(path)
        }
    } else {
        None
    }
}

fn open_input(maybe_path: &Option<PathBuf>) -> Result<File, Error> {
    Ok(if let Some(path) = path_if_some_and_not_dash(maybe_path) {
        File::open(path)?
    } else {
        os_pipe::dup_stdin()?.into()
    })
}

fn open_output(maybe_path: &Option<PathBuf>) -> Result<File, Error> {
    Ok(if let Some(path) = path_if_some_and_not_dash(maybe_path) {
        // Both reading and writing permissions are required for MmapMut.
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?
    } else {
        os_pipe::dup_stdout()?.into()
    })
}

fn maybe_memmap_input(in_file: &File) -> Result<Option<memmap::Mmap>, Error> {
    let metadata = in_file.metadata()?;
    Ok(if !metadata.is_file() {
        // Not a file.
        None
    } else if metadata.len() > isize::max_value() as u64 {
        // Too long to safely map. https://github.com/danburkert/memmap-rs/issues/69
        None
    } else if metadata.len() == 0 {
        // Mapping an empty file currently fails. https://github.com/danburkert/memmap-rs/issues/72
        None
    } else {
        let map = unsafe { memmap::Mmap::map(&in_file)? };
        assert!(map.len() <= isize::max_value() as usize);
        Some(map)
    })
}

fn maybe_memmap_output(
    out_file: &File,
    target_len: u128,
) -> Result<Option<memmap::MmapMut>, Error> {
    if target_len > u64::max_value() as u128 {
        panic!(format!("unreasonable target length: {}", target_len));
    }
    let metadata = out_file.metadata()?;
    Ok(if !metadata.is_file() {
        // Not a file.
        None
    } else if metadata.len() != 0 {
        // The output file hasn't been truncated. Likely opened in append mode.
        None
    } else if target_len == 0 {
        // Mapping an empty file currently fails. https://github.com/danburkert/memmap-rs/issues/72
        None
    } else if target_len > isize::max_value() as u128 {
        // Too long to safely map. https://github.com/danburkert/memmap-rs/issues/69
        None
    } else {
        out_file.set_len(target_len as u64)?;
        let map = unsafe { memmap::MmapMut::map_mut(&out_file)? };
        assert_eq!(map.len() as u128, target_len);
        Some(map)
    })
}

fn confirm_real_file(file: &File, name: &str) -> Result<(), Error> {
    if !file.metadata()?.is_file() {
        Err(err_msg(format!("{} must be a real file", name)))
    } else {
        Ok(())
    }
}

fn parse_hash(args: &Args) -> Result<[u8; bao::hash::HASH_SIZE], Error> {
    let hash_vec = hex::decode(&args.arg_hash).map_err(|_| err_msg("invalid hex"))?;
    if hash_vec.len() != bao::hash::HASH_SIZE {
        return Err(err_msg("wrong length hash"));
    };
    Ok(*array_ref!(hash_vec, 0, bao::hash::HASH_SIZE))
}

// When streaming out decoded content, it's acceptable for the caller to pipe us
// into e.g. `head -c 100`. We catch closed pipe errors in that case and avoid
// erroring out. When encoding, though, we let those errors stay noisy, since
// truncating an encoding is almost never correct.
fn allow_broken_pipe<T>(result: io::Result<T>) -> io::Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(e) => if e.kind() == io::ErrorKind::BrokenPipe {
            Ok(())
        } else {
            Err(e)
        },
    }
}
