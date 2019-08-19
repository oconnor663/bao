use arrayref::array_ref;
use failure::{err_msg, Error};
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

// Note that docopt.rs currently has a bug related to commands wrapped over multiple lines, so
// don't wrap them. https://github.com/docopt/docopt.rs/issues/244
const USAGE: &str = "
Usage: bao hash [<inputs>...]
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

// std::io::copy will use a buffer that's too small by default, leading to bad
// SIMD performance. The bao::BUF_SIZE constant gives the optimal size.
fn copy_with_big_buffer(mut reader: impl Read, mut writer: impl Write) -> io::Result<u64> {
    let mut buffer = [0; bao::BUF_SIZE];
    let mut total = 0;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                writer.write(&buffer[..n])?;
                total += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

fn hash_one(maybe_path: &Option<PathBuf>) -> Result<bao::Hash, Error> {
    let input = open_input(maybe_path)?;
    if let Some(map) = maybe_memmap_input(&input)? {
        Ok(bao::hash(&map))
    } else {
        let mut hasher = bao::Hasher::new();
        copy_with_big_buffer(input, &mut hasher)?;
        Ok(hasher.finalize())
    }
}

fn hash(args: &Args) -> Result<(), Error> {
    if !args.arg_inputs.is_empty() {
        let mut did_error = false;
        for input in args.arg_inputs.iter() {
            let input_str = input.to_string_lossy();
            // As with b2sum or sha1sum, the multi-arg hash loop prints errors and keeps going.
            // This is more convenient for the user in cases like `bao hash *`, where it's common
            // that some of the inputs will error on read e.g. because they're directories.
            match hash_one(&Some(input.clone())) {
                Ok(hash) => {
                    if args.arg_inputs.len() > 1 {
                        println!("{}  {}", hash.to_hex(), input_str);
                    } else {
                        println!("{}", hash.to_hex());
                    }
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
        let hash = hash_one(&None)?;
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
    let mut encoder = if args.flag_outboard.is_some() {
        bao::encode::Encoder::new_outboard(output.require_file()?)
    } else {
        bao::encode::Encoder::new(output.require_file()?)
    };
    copy_with_big_buffer(&mut input, &mut encoder)?;
    encoder.finalize()?;
    Ok(())
}

fn decode(args: &Args) -> Result<(), Error> {
    let input = open_input(&args.arg_input)?;
    let mut output = open_output(&args.arg_output)?;
    let hash = parse_hash(args)?;
    let outboard;
    let mut generic_decoder;
    let mut file_decoder;
    let mut decoder: &mut dyn Read;
    if args.flag_outboard.is_some() {
        outboard = open_input(&args.flag_outboard)?;
        if let Some(offset) = args.flag_start {
            file_decoder = bao::decode::Decoder::new_outboard(
                input.require_file()?,
                outboard.require_file()?,
                &hash,
            );
            file_decoder.seek(io::SeekFrom::Start(offset))?;
            decoder = &mut file_decoder;
        } else {
            generic_decoder = bao::decode::Decoder::new_outboard(input, outboard, &hash);
            decoder = &mut generic_decoder;
        }
    } else {
        if let Some(offset) = args.flag_start {
            file_decoder = bao::decode::Decoder::new(input.require_file()?, &hash);
            file_decoder.seek(io::SeekFrom::Start(offset))?;
            decoder = &mut file_decoder;
        } else {
            generic_decoder = bao::decode::Decoder::new(input, &hash);
            decoder = &mut generic_decoder;
        }
    }
    if let Some(count) = args.flag_count {
        let mut taker = decoder.take(count);
        allow_broken_pipe(copy_with_big_buffer(&mut taker, &mut output))?;
    } else {
        allow_broken_pipe(copy_with_big_buffer(&mut decoder, &mut output))?;
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
    copy_with_big_buffer(&mut extractor, &mut output)?;
    Ok(())
}

fn decode_slice(args: &Args) -> Result<(), Error> {
    let input = open_input(&args.arg_input)?;
    let mut output = open_output(&args.arg_output)?;
    let hash = parse_hash(&args)?;
    let mut decoder = bao::decode::SliceDecoder::new(input, &hash, args.arg_start, args.arg_count);
    allow_broken_pipe(copy_with_big_buffer(&mut decoder, &mut output))?;
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

fn parse_hash(args: &Args) -> Result<bao::Hash, Error> {
    let hash_vec = hex::decode(&args.arg_hash).map_err(|_| err_msg("invalid hex"))?;
    if hash_vec.len() != bao::HASH_SIZE {
        return Err(err_msg("wrong length hash"));
    };
    Ok((*array_ref!(hash_vec, 0, bao::HASH_SIZE)).into())
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
