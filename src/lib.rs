#[macro_use]
extern crate arrayref;
extern crate arrayvec;
extern crate blake2_c;
extern crate byteorder;
extern crate crossbeam;
#[macro_use]
extern crate lazy_static;
extern crate num_cpus;
extern crate rayon;

#[cfg(test)]
#[macro_use]
extern crate duct;
#[cfg(test)]
extern crate hex;

pub mod decoder;
pub mod encoder;
pub mod hash;
pub mod io;
mod unverified;
