//! # falcon
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * falcon-512 - clean
//! * falcon-1024 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod falcon1024;
pub mod falcon512;
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
