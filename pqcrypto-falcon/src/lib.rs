//! # falcon
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * falcon-512 - clean
//! * falcon-padded-512 - clean
//! * falcon-1024 - clean
//! * falcon-padded-1024 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![no_std]
#![allow(clippy::len_without_is_empty)]

// For no-std vectors
extern crate alloc;

// For tests
#[cfg(feature = "std")]
extern crate std;

pub mod falcon1024;
pub mod falcon512;
pub mod falconpadded1024;
pub mod falconpadded512;
pub mod ffi;

pub use crate::falcon1024::{
    detached_sign as falcon1024_detached_sign, keypair as falcon1024_keypair,
    open as falcon1024_open, public_key_bytes as falcon1024_public_key_bytes,
    secret_key_bytes as falcon1024_secret_key_bytes, sign as falcon1024_sign,
    signature_bytes as falcon1024_signature_bytes,
    verify_detached_signature as falcon1024_verify_detached_signature,
};
pub use crate::falcon512::{
    detached_sign as falcon512_detached_sign, keypair as falcon512_keypair, open as falcon512_open,
    public_key_bytes as falcon512_public_key_bytes, secret_key_bytes as falcon512_secret_key_bytes,
    sign as falcon512_sign, signature_bytes as falcon512_signature_bytes,
    verify_detached_signature as falcon512_verify_detached_signature,
};
pub use crate::falconpadded1024::{
    detached_sign as falconpadded1024_detached_sign, keypair as falconpadded1024_keypair,
    open as falconpadded1024_open, public_key_bytes as falconpadded1024_public_key_bytes,
    secret_key_bytes as falconpadded1024_secret_key_bytes, sign as falconpadded1024_sign,
    signature_bytes as falconpadded1024_signature_bytes,
    verify_detached_signature as falconpadded1024_verify_detached_signature,
};
pub use crate::falconpadded512::{
    detached_sign as falconpadded512_detached_sign, keypair as falconpadded512_keypair,
    open as falconpadded512_open, public_key_bytes as falconpadded512_public_key_bytes,
    secret_key_bytes as falconpadded512_secret_key_bytes, sign as falconpadded512_sign,
    signature_bytes as falconpadded512_signature_bytes,
    verify_detached_signature as falconpadded512_verify_detached_signature,
};
