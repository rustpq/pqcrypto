//! # ntru
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * ntruhps2048509 - clean
//! * ntruhps2048677 - clean
//! * ntruhps4096821 - clean
//! * ntruhrss701 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod ffi;

pub mod ntruhps2048509;
pub mod ntruhps2048677;
pub mod ntruhps4096821;
pub mod ntruhrss701;

pub use crate::ntruhps2048509::{
    ciphertext_bytes as ntruhps2048509_ciphertext_bytes, decapsulate as ntruhps2048509_decapsulate,
    encapsulate as ntruhps2048509_encapsulate, keypair as ntruhps2048509_keypair,
    public_key_bytes as ntruhps2048509_public_key_bytes,
    secret_key_bytes as ntruhps2048509_secret_key_bytes,
    shared_secret_bytes as ntruhps2048509_shared_secret_bytes,
};
pub use crate::ntruhps2048677::{
    ciphertext_bytes as ntruhps2048677_ciphertext_bytes, decapsulate as ntruhps2048677_decapsulate,
    encapsulate as ntruhps2048677_encapsulate, keypair as ntruhps2048677_keypair,
    public_key_bytes as ntruhps2048677_public_key_bytes,
    secret_key_bytes as ntruhps2048677_secret_key_bytes,
    shared_secret_bytes as ntruhps2048677_shared_secret_bytes,
};
pub use crate::ntruhps4096821::{
    ciphertext_bytes as ntruhps4096821_ciphertext_bytes, decapsulate as ntruhps4096821_decapsulate,
    encapsulate as ntruhps4096821_encapsulate, keypair as ntruhps4096821_keypair,
    public_key_bytes as ntruhps4096821_public_key_bytes,
    secret_key_bytes as ntruhps4096821_secret_key_bytes,
    shared_secret_bytes as ntruhps4096821_shared_secret_bytes,
};
pub use crate::ntruhrss701::{
    ciphertext_bytes as ntruhrss701_ciphertext_bytes, decapsulate as ntruhrss701_decapsulate,
    encapsulate as ntruhrss701_encapsulate, keypair as ntruhrss701_keypair,
    public_key_bytes as ntruhrss701_public_key_bytes,
    secret_key_bytes as ntruhrss701_secret_key_bytes,
    shared_secret_bytes as ntruhrss701_shared_secret_bytes,
};
