//! # hqc
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * hqc-128 - clean
//! * hqc-192 - clean
//! * hqc-256 - clean
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

pub mod ffi;
pub mod hqc128;
pub mod hqc192;
pub mod hqc256;

pub use crate::hqc128::{
    ciphertext_bytes as hqc128_ciphertext_bytes, decapsulate as hqc128_decapsulate,
    encapsulate as hqc128_encapsulate, keypair as hqc128_keypair,
    public_key_bytes as hqc128_public_key_bytes, secret_key_bytes as hqc128_secret_key_bytes,
    shared_secret_bytes as hqc128_shared_secret_bytes,
};
pub use crate::hqc192::{
    ciphertext_bytes as hqc192_ciphertext_bytes, decapsulate as hqc192_decapsulate,
    encapsulate as hqc192_encapsulate, keypair as hqc192_keypair,
    public_key_bytes as hqc192_public_key_bytes, secret_key_bytes as hqc192_secret_key_bytes,
    shared_secret_bytes as hqc192_shared_secret_bytes,
};
pub use crate::hqc256::{
    ciphertext_bytes as hqc256_ciphertext_bytes, decapsulate as hqc256_decapsulate,
    encapsulate as hqc256_encapsulate, keypair as hqc256_keypair,
    public_key_bytes as hqc256_public_key_bytes, secret_key_bytes as hqc256_secret_key_bytes,
    shared_secret_bytes as hqc256_shared_secret_bytes,
};
