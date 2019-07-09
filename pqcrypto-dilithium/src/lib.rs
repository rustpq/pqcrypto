//! # dilithium
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * dilithium2 - clean
//! * dilithium3 - clean
//! * dilithium4 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod ffi;

pub mod dilithium2;
pub mod dilithium3;
pub mod dilithium4;

pub use crate::dilithium2::{
    detached_sign as dilithium2_detached_sign, keypair as dilithium2_keypair,
    open as dilithium2_open, public_key_bytes as dilithium2_public_key_bytes,
    secret_key_bytes as dilithium2_secret_key_bytes, sign as dilithium2_sign,
    signature_bytes as dilithium2_signature_bytes,
    verify_detached_signature as dilithium2_verify_detached_signature,
};
pub use crate::dilithium3::{
    detached_sign as dilithium3_detached_sign, keypair as dilithium3_keypair,
    open as dilithium3_open, public_key_bytes as dilithium3_public_key_bytes,
    secret_key_bytes as dilithium3_secret_key_bytes, sign as dilithium3_sign,
    signature_bytes as dilithium3_signature_bytes,
    verify_detached_signature as dilithium3_verify_detached_signature,
};
pub use crate::dilithium4::{
    detached_sign as dilithium4_detached_sign, keypair as dilithium4_keypair,
    open as dilithium4_open, public_key_bytes as dilithium4_public_key_bytes,
    secret_key_bytes as dilithium4_secret_key_bytes, sign as dilithium4_sign,
    signature_bytes as dilithium4_signature_bytes,
    verify_detached_signature as dilithium4_verify_detached_signature,
};
