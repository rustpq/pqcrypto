//! # hqc
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * hqc-128-1-cca2 - leaktime
//! * hqc-192-1-cca2 - leaktime
//! * hqc-192-2-cca2 - leaktime
//! * hqc-256-1-cca2 - leaktime
//! * hqc-256-2-cca2 - leaktime
//! * hqc-256-3-cca2 - leaktime
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!
//! # Notes
//! This implementation is not constant-time! This means that it is not
//! secure.  This crate may remove the ``leaktime`` implementation at any
//! point.

#![allow(clippy::len_without_is_empty)]

pub mod ffi;
pub mod hqc1281cca2;
pub mod hqc1921cca2;
pub mod hqc1922cca2;
pub mod hqc2561cca2;
pub mod hqc2562cca2;
pub mod hqc2563cca2;

pub use crate::hqc1281cca2::{
    ciphertext_bytes as hqc1281cca2_ciphertext_bytes, decapsulate as hqc1281cca2_decapsulate,
    encapsulate as hqc1281cca2_encapsulate, keypair as hqc1281cca2_keypair,
    public_key_bytes as hqc1281cca2_public_key_bytes,
    secret_key_bytes as hqc1281cca2_secret_key_bytes,
    shared_secret_bytes as hqc1281cca2_shared_secret_bytes,
};
pub use crate::hqc1921cca2::{
    ciphertext_bytes as hqc1921cca2_ciphertext_bytes, decapsulate as hqc1921cca2_decapsulate,
    encapsulate as hqc1921cca2_encapsulate, keypair as hqc1921cca2_keypair,
    public_key_bytes as hqc1921cca2_public_key_bytes,
    secret_key_bytes as hqc1921cca2_secret_key_bytes,
    shared_secret_bytes as hqc1921cca2_shared_secret_bytes,
};
pub use crate::hqc1922cca2::{
    ciphertext_bytes as hqc1922cca2_ciphertext_bytes, decapsulate as hqc1922cca2_decapsulate,
    encapsulate as hqc1922cca2_encapsulate, keypair as hqc1922cca2_keypair,
    public_key_bytes as hqc1922cca2_public_key_bytes,
    secret_key_bytes as hqc1922cca2_secret_key_bytes,
    shared_secret_bytes as hqc1922cca2_shared_secret_bytes,
};
pub use crate::hqc2561cca2::{
    ciphertext_bytes as hqc2561cca2_ciphertext_bytes, decapsulate as hqc2561cca2_decapsulate,
    encapsulate as hqc2561cca2_encapsulate, keypair as hqc2561cca2_keypair,
    public_key_bytes as hqc2561cca2_public_key_bytes,
    secret_key_bytes as hqc2561cca2_secret_key_bytes,
    shared_secret_bytes as hqc2561cca2_shared_secret_bytes,
};
pub use crate::hqc2562cca2::{
    ciphertext_bytes as hqc2562cca2_ciphertext_bytes, decapsulate as hqc2562cca2_decapsulate,
    encapsulate as hqc2562cca2_encapsulate, keypair as hqc2562cca2_keypair,
    public_key_bytes as hqc2562cca2_public_key_bytes,
    secret_key_bytes as hqc2562cca2_secret_key_bytes,
    shared_secret_bytes as hqc2562cca2_shared_secret_bytes,
};
pub use crate::hqc2563cca2::{
    ciphertext_bytes as hqc2563cca2_ciphertext_bytes, decapsulate as hqc2563cca2_decapsulate,
    encapsulate as hqc2563cca2_encapsulate, keypair as hqc2563cca2_keypair,
    public_key_bytes as hqc2563cca2_public_key_bytes,
    secret_key_bytes as hqc2563cca2_secret_key_bytes,
    shared_secret_bytes as hqc2563cca2_shared_secret_bytes,
};
