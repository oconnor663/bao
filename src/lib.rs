//! [Repo](https://github.com/oconnor663/bao) —
//! [Crate](https://crates.io/crates/bao) —
//! [Spec](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
//!
//! This crate implements the Bao hash function and encoding format. The `bao` [command line
//! utility](https://github.com/oconnor663/bao) is built on top of it. For more about how Bao works
//! and what the encoding format is doing, see the [command line
//! readme](https://github.com/oconnor663/bao/blob/master/README.md) and the [full
//! specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md).
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

pub mod decode;
pub mod encode;
pub mod hash;
