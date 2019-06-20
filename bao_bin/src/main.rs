#[macro_use]
extern crate arrayref;
extern crate bao;
extern crate docopt;
extern crate failure;
extern crate hex;
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
    let mut input = open_input(maybe_path)?;
    Ok(if args.flag_outboard.is_some() {
        let mut outboard = open_input(&args.flag_outboard)?;
        bao::decode::hash_from_outboard_encoded(&mut input, &mut outboard)?
    } else if args.flag_encoded {
        bao::decode::hash_from_encoded(&mut input)?
    } else if let Some(map) = maybe_memmap_input(&input)? {
        bao::hash::hash(&map)
    } else {
        let mut writer = bao::hash::Writer::new();
        io::copy(&mut input, &mut writer)?;
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
                    println!("{}  {}", hash.to_hex(), input_str);
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
        println!("{}", hash.to_hex());
    }
    Ok(())
}

fn encode(args: &Args) -> Result<(), Error> {
    let mut input = open_input(&args.arg_input)?;
    let out_maybe_path = if args.flag_outboard.is_some() {
        &args.flag_outboard
    } else {
        &args.arg_output
    };
    let output = open_output(out_maybe_path)?;
    if let Some(in_map) = maybe_memmap_input(&input)? {
        let target_len = if args.flag_outboard.is_some() {
            bao::encode::outboard_size(in_map.len() as u64)
        } else {
            bao::encode::encoded_size(in_map.len() as u64)
        };
        if let Some(mut out_map) = maybe_memmap_output(&output, target_len)? {
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
    let mut writer;
    if args.flag_outboard.is_some() {
        writer = bao::encode::Writer::new_outboard(output.require_file()?);
    } else {
        writer = bao::encode::Writer::new(output.require_file()?);
    };
    io::copy(&mut input, &mut writer)?;
    writer.finish()?;
    Ok(())
}

fn decode(args: &Args) -> Result<(), Error> {
    let input = open_input(&args.arg_input)?;
    let mut output = open_output(&args.arg_output)?;
    let hash = parse_hash(args)?;
    // If we're not seeking or outboard or stdout, try to memmap the files.
    let special_options =
        args.flag_start.is_some() || args.flag_count.is_some() || args.flag_outboard.is_some();
    if !special_options {
        if let Some(in_map) = maybe_memmap_input(&input)? {
            let content_len = bao::decode::parse_and_check_content_len(&in_map)?;
            if let Some(mut out_map) = maybe_memmap_output(&output, content_len as u128)? {
                bao::decode::decode(&in_map, &mut out_map, &hash)?;
                return Ok(());
            }
        }
    }
    // If the files weren't mappable, or if we're seeking or outboard, fall back to the reader.
    // Unfortunately there are a 2x2 different cases here, becuase seeking requires statically
    // knowing that the inputs are files.
    let outboard;
    let mut generic_reader;
    let mut file_reader;
    let mut reader: &mut dyn Read;
    if args.flag_outboard.is_some() {
        outboard = open_input(&args.flag_outboard)?;
        if let Some(offset) = args.flag_start {
            file_reader = bao::decode::Reader::new_outboard(
                input.require_file()?,
                outboard.require_file()?,
                &hash,
            );
            file_reader.seek(io::SeekFrom::Start(offset))?;
            reader = &mut file_reader;
        } else {
            generic_reader = bao::decode::Reader::new_outboard(input, outboard, &hash);
            reader = &mut generic_reader;
        }
    } else {
        if let Some(offset) = args.flag_start {
            file_reader = bao::decode::Reader::new(input.require_file()?, &hash);
            file_reader.seek(io::SeekFrom::Start(offset))?;
            reader = &mut file_reader;
        } else {
            generic_reader = bao::decode::Reader::new(input, &hash);
            reader = &mut generic_reader;
        }
    }
    if let Some(count) = args.flag_count {
        let mut taker = reader.take(count);
        allow_broken_pipe(io::copy(&mut taker, &mut output))?;
    } else {
        allow_broken_pipe(io::copy(&mut reader, &mut output))?;
    }
    Ok(())
}

fn slice(args: &Args) -> Result<(), Error> {
    let input = open_input(&args.arg_input)?;
    let mut output = open_output(&args.arg_output)?;
    // Slice extraction requires seek.
    let outboard;
    let mut extractor;
    if args.flag_outboard.is_some() {
        outboard = open_input(&args.flag_outboard)?;
        extractor = bao::encode::SliceExtractor::new_outboard(
            input.require_file()?,
            outboard.require_file()?,
            args.arg_start,
            args.arg_count,
        );
    } else {
        extractor =
            bao::encode::SliceExtractor::new(input.require_file()?, args.arg_start, args.arg_count);
    }
    io::copy(&mut extractor, &mut output)?;
    Ok(())
}

fn decode_slice(args: &Args) -> Result<(), Error> {
    let input = open_input(&args.arg_input)?;
    let mut output = open_output(&args.arg_output)?;
    let hash = parse_hash(&args)?;
    let mut reader = bao::decode::SliceReader::new(input, &hash, args.arg_start, args.arg_count);
    allow_broken_pipe(io::copy(&mut reader, &mut output))?;
    Ok(())
}

fn open_input(maybe_path: &Option<PathBuf>) -> Result<Input, Error> {
    Ok(
        if let Some(ref path) = path_if_some_and_not_dash(maybe_path) {
            Input::File(File::open(path)?)
        } else {
            Input::Stdin
        },
    )
}

enum Input {
    Stdin,
    File(File),
}

impl Input {
    fn require_file(self) -> Result<File, Error> {
        match self {
            Input::Stdin => Err(err_msg(format!("input must be a real file"))),
            Input::File(file) => Ok(file),
        }
    }
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            Input::Stdin => io::stdin().read(buf),
            Input::File(ref mut file) => file.read(buf),
        }
    }
}

fn open_output(maybe_path: &Option<PathBuf>) -> Result<Output, Error> {
    if let Some(ref path) = path_if_some_and_not_dash(maybe_path) {
        // Both reading and writing permissions are required for MmapMut.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        return Ok(Output::File(file));
    }
    Ok(Output::Stdout)
}

enum Output {
    Stdout,
    File(File),
}

impl Output {
    fn require_file(self) -> Result<File, Error> {
        match self {
            Output::Stdout => Err(err_msg(format!("output must be a real file"))),
            Output::File(file) => Ok(file),
        }
    }
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            Output::Stdout => io::stdout().write(buf),
            Output::File(ref mut file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            Output::Stdout => io::stdout().flush(),
            Output::File(ref mut file) => file.flush(),
        }
    }
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

fn maybe_memmap_input(input: &Input) -> Result<Option<memmap::Mmap>, Error> {
    let in_file = match *input {
        Input::Stdin => return Ok(None),
        Input::File(ref file) => file,
    };
    let metadata = in_file.metadata()?;
    Ok(if !metadata.is_file() {
        // Not a real file.
        None
    } else if metadata.len() > isize::max_value() as u64 {
        // Too long to safely map. https://github.com/danburkert/memmap-rs/issues/69
        None
    } else if metadata.len() == 0 {
        // Mapping an empty file currently fails. https://github.com/danburkert/memmap-rs/issues/72
        None
    } else {
        // Explicitly set the length of the memory map, so that filesystem changes can't race to
        // violate the invariants we just checked.
        let map = unsafe {
            memmap::MmapOptions::new()
                .len(metadata.len() as usize)
                .map(&in_file)?
        };
        Some(map)
    })
}

fn maybe_memmap_output(
    output: &Output,
    target_len: u128,
) -> Result<Option<memmap::MmapMut>, Error> {
    let out_file = match *output {
        Output::Stdout => return Ok(None),
        Output::File(ref file) => file,
    };
    if target_len > u64::max_value() as u128 {
        panic!(format!("unreasonable target length: {}", target_len));
    }
    let metadata = out_file.metadata()?;
    Ok(if !metadata.is_file() {
        // Not a real file.
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
        // Explicitly set the length of the memory map, so that filesystem changes can't race to
        // violate the invariants we just checked.
        let map = unsafe {
            memmap::MmapOptions::new()
                .len(target_len as usize)
                .map_mut(&out_file)?
        };
        Some(map)
    })
}

fn parse_hash(args: &Args) -> Result<bao::hash::Hash, Error> {
    let hash_vec = hex::decode(&args.arg_hash).map_err(|_| err_msg("invalid hex"))?;
    if hash_vec.len() != bao::hash::HASH_SIZE {
        return Err(err_msg("wrong length hash"));
    };
    Ok(bao::hash::Hash::new(*array_ref!(
        hash_vec,
        0,
        bao::hash::HASH_SIZE
    )))
}

// When streaming out decoded content, it's acceptable for the caller to pipe us
// into e.g. `head -c 100`. We catch closed pipe errors in that case and avoid
// erroring out. When encoding, though, we let those errors stay noisy, since
// truncating an encoding is almost never correct.
fn allow_broken_pipe<T>(result: io::Result<T>) -> io::Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.kind() == io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}
