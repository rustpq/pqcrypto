//! # ntru
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * ntruhps2048509 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

pub mod ffi;

pub mod ntruhps2048509;

pub use crate::ntruhps2048509::{
    ciphertext_bytes as ntruhps2048509_ciphertext_bytes, decapsulate as ntruhps2048509_decapsulate,
    encapsulate as ntruhps2048509_encapsulate, keypair as ntruhps2048509_keypair,
    public_key_bytes as ntruhps2048509_public_key_bytes,
    secret_key_bytes as ntruhps2048509_secret_key_bytes,
    shared_secret_bytes as ntruhps2048509_shared_secret_bytes,
};
