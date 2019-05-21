//! # mqdss
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * mqdss-48 - clean
//! * mqdss-64 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

pub mod ffi;

pub mod mqdss48;
pub mod mqdss64;

pub use crate::mqdss48::{
    detached_sign as mqdss48_detached_sign, keypair as mqdss48_keypair, open as mqdss48_open,
    public_key_bytes as mqdss48_public_key_bytes, secret_key_bytes as mqdss48_secret_key_bytes,
    sign as mqdss48_sign, signature_bytes as mqdss48_signature_bytes,
    verify_detached_signature as mqdss48_verify_detached_signature,
};
pub use crate::mqdss64::{
    detached_sign as mqdss64_detached_sign, keypair as mqdss64_keypair, open as mqdss64_open,
    public_key_bytes as mqdss64_public_key_bytes, secret_key_bytes as mqdss64_secret_key_bytes,
    sign as mqdss64_sign, signature_bytes as mqdss64_signature_bytes,
    verify_detached_signature as mqdss64_verify_detached_signature,
};
