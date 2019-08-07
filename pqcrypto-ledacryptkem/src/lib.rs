//! # ledacryptkem
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * ledakemlt12 - leaktime
//! * ledakemlt32 - leaktime
//! * ledakemlt52 - leaktime
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!
//! # Notes
//! This implementation is not constant-time! This means that it is not
//! secure.  This crate may remove the ``leaktime`` implementation at any
//! point.

#![allow(clippy::len_without_is_empty)]

pub mod ffi;

pub mod ledakemlt12;
pub mod ledakemlt32;
pub mod ledakemlt52;

pub use crate::ledakemlt12::{
    ciphertext_bytes as ledakemlt12_ciphertext_bytes, decapsulate as ledakemlt12_decapsulate,
    encapsulate as ledakemlt12_encapsulate, keypair as ledakemlt12_keypair,
    public_key_bytes as ledakemlt12_public_key_bytes,
    secret_key_bytes as ledakemlt12_secret_key_bytes,
    shared_secret_bytes as ledakemlt12_shared_secret_bytes,
};
pub use crate::ledakemlt32::{
    ciphertext_bytes as ledakemlt32_ciphertext_bytes, decapsulate as ledakemlt32_decapsulate,
    encapsulate as ledakemlt32_encapsulate, keypair as ledakemlt32_keypair,
    public_key_bytes as ledakemlt32_public_key_bytes,
    secret_key_bytes as ledakemlt32_secret_key_bytes,
    shared_secret_bytes as ledakemlt32_shared_secret_bytes,
};
pub use crate::ledakemlt52::{
    ciphertext_bytes as ledakemlt52_ciphertext_bytes, decapsulate as ledakemlt52_decapsulate,
    encapsulate as ledakemlt52_encapsulate, keypair as ledakemlt52_keypair,
    public_key_bytes as ledakemlt52_public_key_bytes,
    secret_key_bytes as ledakemlt52_secret_key_bytes,
    shared_secret_bytes as ledakemlt52_shared_secret_bytes,
};
