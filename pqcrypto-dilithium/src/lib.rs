//! # dilithium
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * dilithium2 - clean
//! * dilithium3 - clean
//! * dilithium5 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod dilithium2;
pub mod dilithium3;
pub mod dilithium5;
pub mod ffi;

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
pub use crate::dilithium5::{
    detached_sign as dilithium5_detached_sign, keypair as dilithium5_keypair,
    open as dilithium5_open, public_key_bytes as dilithium5_public_key_bytes,
    secret_key_bytes as dilithium5_secret_key_bytes, sign as dilithium5_sign,
    signature_bytes as dilithium5_signature_bytes,
    verify_detached_signature as dilithium5_verify_detached_signature,
};
