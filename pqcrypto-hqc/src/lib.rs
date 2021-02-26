//! # hqc
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * hqc-rmrs-128 - clean
//! * hqc-rmrs-192 - clean
//! * hqc-rmrs-256 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod ffi;
pub mod hqcrmrs128;
pub mod hqcrmrs192;
pub mod hqcrmrs256;

pub use crate::hqcrmrs128::{
    ciphertext_bytes as hqcrmrs128_ciphertext_bytes, decapsulate as hqcrmrs128_decapsulate,
    encapsulate as hqcrmrs128_encapsulate, keypair as hqcrmrs128_keypair,
    public_key_bytes as hqcrmrs128_public_key_bytes,
    secret_key_bytes as hqcrmrs128_secret_key_bytes,
    shared_secret_bytes as hqcrmrs128_shared_secret_bytes,
};
pub use crate::hqcrmrs192::{
    ciphertext_bytes as hqcrmrs192_ciphertext_bytes, decapsulate as hqcrmrs192_decapsulate,
    encapsulate as hqcrmrs192_encapsulate, keypair as hqcrmrs192_keypair,
    public_key_bytes as hqcrmrs192_public_key_bytes,
    secret_key_bytes as hqcrmrs192_secret_key_bytes,
    shared_secret_bytes as hqcrmrs192_shared_secret_bytes,
};
pub use crate::hqcrmrs256::{
    ciphertext_bytes as hqcrmrs256_ciphertext_bytes, decapsulate as hqcrmrs256_decapsulate,
    encapsulate as hqcrmrs256_encapsulate, keypair as hqcrmrs256_keypair,
    public_key_bytes as hqcrmrs256_public_key_bytes,
    secret_key_bytes as hqcrmrs256_secret_key_bytes,
    shared_secret_bytes as hqcrmrs256_shared_secret_bytes,
};
