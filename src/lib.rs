//! [Repo](https://github.com/oconnor663/bao) —
//! [Crate](https://crates.io/crates/bao) —
//! [Spec](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
//!
//! This crate implements the Bao hash function and encoding format. It powers the `bao` [command
//! line utility](https://github.com/oconnor663/bao).
//!
//! # Example
//!
//! ```
//! let hash_at_once = bao::hash::hash(b"input bytes");
//!
//! let mut hasher = bao::hash::Writer::new();
//! hasher.update(b"input");
//! hasher.update(b" ");
//! hasher.update(b"bytes");
//! let hash_incremental = hasher.finish();
//!
//! assert_eq!(hash_at_once, hash_incremental);
//! ```

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

pub mod decode;
pub mod encode;
pub mod hash;
