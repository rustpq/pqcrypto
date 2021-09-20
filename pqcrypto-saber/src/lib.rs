//! # saber
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * firesaber - clean
//! * lightsaber - clean
//! * saber - clean
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
pub mod firesaber;
pub mod lightsaber;
pub mod saber;

pub use crate::firesaber::{
    ciphertext_bytes as firesaber_ciphertext_bytes, decapsulate as firesaber_decapsulate,
    encapsulate as firesaber_encapsulate, keypair as firesaber_keypair,
    public_key_bytes as firesaber_public_key_bytes, secret_key_bytes as firesaber_secret_key_bytes,
    shared_secret_bytes as firesaber_shared_secret_bytes,
};
pub use crate::lightsaber::{
    ciphertext_bytes as lightsaber_ciphertext_bytes, decapsulate as lightsaber_decapsulate,
    encapsulate as lightsaber_encapsulate, keypair as lightsaber_keypair,
    public_key_bytes as lightsaber_public_key_bytes,
    secret_key_bytes as lightsaber_secret_key_bytes,
    shared_secret_bytes as lightsaber_shared_secret_bytes,
};
pub use crate::saber::{
    ciphertext_bytes as saber_ciphertext_bytes, decapsulate as saber_decapsulate,
    encapsulate as saber_encapsulate, keypair as saber_keypair,
    public_key_bytes as saber_public_key_bytes, secret_key_bytes as saber_secret_key_bytes,
    shared_secret_bytes as saber_shared_secret_bytes,
};
