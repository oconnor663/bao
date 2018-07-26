#[macro_use]
extern crate arrayref;
extern crate arrayvec;
extern crate blake2_c;
extern crate byteorder;
extern crate crossbeam;
extern crate num_cpus;
extern crate rayon;

#[cfg(test)]
#[macro_use]
extern crate duct;
#[cfg(test)]
extern crate hex;

pub mod decode;
pub mod encode;
pub mod hash;
pub mod io;
mod unverified;
