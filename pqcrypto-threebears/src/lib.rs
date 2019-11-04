//! # threebears
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * babybear - clean
//! * mamabear - clean
//! * papabear - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod ffi;

pub mod babybear;
pub mod mamabear;
pub mod papabear;

pub use crate::babybear::{
    ciphertext_bytes as babybear_ciphertext_bytes, decapsulate as babybear_decapsulate,
    encapsulate as babybear_encapsulate, keypair as babybear_keypair,
    public_key_bytes as babybear_public_key_bytes, secret_key_bytes as babybear_secret_key_bytes,
    shared_secret_bytes as babybear_shared_secret_bytes,
};
pub use crate::mamabear::{
    ciphertext_bytes as mamabear_ciphertext_bytes, decapsulate as mamabear_decapsulate,
    encapsulate as mamabear_encapsulate, keypair as mamabear_keypair,
    public_key_bytes as mamabear_public_key_bytes, secret_key_bytes as mamabear_secret_key_bytes,
    shared_secret_bytes as mamabear_shared_secret_bytes,
};
pub use crate::papabear::{
    ciphertext_bytes as papabear_ciphertext_bytes, decapsulate as papabear_decapsulate,
    encapsulate as papabear_encapsulate, keypair as papabear_keypair,
    public_key_bytes as papabear_public_key_bytes, secret_key_bytes as papabear_secret_key_bytes,
    shared_secret_bytes as papabear_shared_secret_bytes,
};
