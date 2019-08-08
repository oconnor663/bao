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
//! The `encode` and `decode` modules require the `std` feature, which is
//! enabled by default.
//!
//! **Caution!** Not yet suitable for production use. The output of Bao isn't
//! stable. There might be more changes before 1.0.
//!
//! # Example
//!
//! ```
//! let expected = "6d1128fa367a8d7f6f8dc946ede523e61b881a8b3463014520ad946dad75f820";
//! let hash = bao::hash::hash(b"input bytes");
//! assert_eq!(expected, &hash.to_hex());
//!
//! let mut hasher = bao::hash::Hasher::new();
//! hasher.update(b"input");
//! hasher.update(b" ");
//! hasher.update(b"bytes");
//! assert_eq!(hash, hasher.finalize());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
pub mod decode;
#[cfg(feature = "std")]
pub mod encode;
pub mod hash;
