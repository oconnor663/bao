#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate core;

#[macro_use]
extern crate arrayref;
extern crate arrayvec;
extern crate blake2b_simd;
extern crate byteorder;
extern crate constant_time_eq;
extern crate copy_in_place;
#[cfg(feature = "std")]
extern crate rayon;

#[cfg(test)]
#[macro_use]
extern crate duct;
#[cfg(test)]
extern crate hex;

pub mod decode;
pub mod encode;
pub mod hash;
