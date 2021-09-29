//! # ntruprime
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * ntrulpr653 - clean
//! * ntrulpr761 - clean
//! * ntrulpr857 - clean
//! * sntrup653 - clean
//! * sntrup761 - clean
//! * sntrup857 - clean
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
pub mod ntrulpr653;
pub mod ntrulpr761;
pub mod ntrulpr857;
pub mod sntrup653;
pub mod sntrup761;
pub mod sntrup857;

pub use crate::ntrulpr653::{
    ciphertext_bytes as ntrulpr653_ciphertext_bytes, decapsulate as ntrulpr653_decapsulate,
    encapsulate as ntrulpr653_encapsulate, keypair as ntrulpr653_keypair,
    public_key_bytes as ntrulpr653_public_key_bytes,
    secret_key_bytes as ntrulpr653_secret_key_bytes,
    shared_secret_bytes as ntrulpr653_shared_secret_bytes,
};
pub use crate::ntrulpr761::{
    ciphertext_bytes as ntrulpr761_ciphertext_bytes, decapsulate as ntrulpr761_decapsulate,
    encapsulate as ntrulpr761_encapsulate, keypair as ntrulpr761_keypair,
    public_key_bytes as ntrulpr761_public_key_bytes,
    secret_key_bytes as ntrulpr761_secret_key_bytes,
    shared_secret_bytes as ntrulpr761_shared_secret_bytes,
};
pub use crate::ntrulpr857::{
    ciphertext_bytes as ntrulpr857_ciphertext_bytes, decapsulate as ntrulpr857_decapsulate,
    encapsulate as ntrulpr857_encapsulate, keypair as ntrulpr857_keypair,
    public_key_bytes as ntrulpr857_public_key_bytes,
    secret_key_bytes as ntrulpr857_secret_key_bytes,
    shared_secret_bytes as ntrulpr857_shared_secret_bytes,
};
pub use crate::sntrup653::{
    ciphertext_bytes as sntrup653_ciphertext_bytes, decapsulate as sntrup653_decapsulate,
    encapsulate as sntrup653_encapsulate, keypair as sntrup653_keypair,
    public_key_bytes as sntrup653_public_key_bytes, secret_key_bytes as sntrup653_secret_key_bytes,
    shared_secret_bytes as sntrup653_shared_secret_bytes,
};
pub use crate::sntrup761::{
    ciphertext_bytes as sntrup761_ciphertext_bytes, decapsulate as sntrup761_decapsulate,
    encapsulate as sntrup761_encapsulate, keypair as sntrup761_keypair,
    public_key_bytes as sntrup761_public_key_bytes, secret_key_bytes as sntrup761_secret_key_bytes,
    shared_secret_bytes as sntrup761_shared_secret_bytes,
};
pub use crate::sntrup857::{
    ciphertext_bytes as sntrup857_ciphertext_bytes, decapsulate as sntrup857_decapsulate,
    encapsulate as sntrup857_encapsulate, keypair as sntrup857_keypair,
    public_key_bytes as sntrup857_public_key_bytes, secret_key_bytes as sntrup857_secret_key_bytes,
    shared_secret_bytes as sntrup857_shared_secret_bytes,
};
