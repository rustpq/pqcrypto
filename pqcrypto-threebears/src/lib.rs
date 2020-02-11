//! # threebears
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * babybear - clean
//! * mamabear - clean
//! * papabear - clean
//! * papabear-ephem - clean
//! * mamabear-ephem - clean
//! * babybear-ephem - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod ffi;

pub mod babybear;
pub mod babybearephem;
pub mod mamabear;
pub mod mamabearephem;
pub mod papabear;
pub mod papabearephem;

pub use crate::babybear::{
    ciphertext_bytes as babybear_ciphertext_bytes, decapsulate as babybear_decapsulate,
    encapsulate as babybear_encapsulate, keypair as babybear_keypair,
    public_key_bytes as babybear_public_key_bytes, secret_key_bytes as babybear_secret_key_bytes,
    shared_secret_bytes as babybear_shared_secret_bytes,
};
pub use crate::babybearephem::{
    ciphertext_bytes as babybearephem_ciphertext_bytes, decapsulate as babybearephem_decapsulate,
    encapsulate as babybearephem_encapsulate, keypair as babybearephem_keypair,
    public_key_bytes as babybearephem_public_key_bytes,
    secret_key_bytes as babybearephem_secret_key_bytes,
    shared_secret_bytes as babybearephem_shared_secret_bytes,
};
pub use crate::mamabear::{
    ciphertext_bytes as mamabear_ciphertext_bytes, decapsulate as mamabear_decapsulate,
    encapsulate as mamabear_encapsulate, keypair as mamabear_keypair,
    public_key_bytes as mamabear_public_key_bytes, secret_key_bytes as mamabear_secret_key_bytes,
    shared_secret_bytes as mamabear_shared_secret_bytes,
};
pub use crate::mamabearephem::{
    ciphertext_bytes as mamabearephem_ciphertext_bytes, decapsulate as mamabearephem_decapsulate,
    encapsulate as mamabearephem_encapsulate, keypair as mamabearephem_keypair,
    public_key_bytes as mamabearephem_public_key_bytes,
    secret_key_bytes as mamabearephem_secret_key_bytes,
    shared_secret_bytes as mamabearephem_shared_secret_bytes,
};
pub use crate::papabear::{
    ciphertext_bytes as papabear_ciphertext_bytes, decapsulate as papabear_decapsulate,
    encapsulate as papabear_encapsulate, keypair as papabear_keypair,
    public_key_bytes as papabear_public_key_bytes, secret_key_bytes as papabear_secret_key_bytes,
    shared_secret_bytes as papabear_shared_secret_bytes,
};
pub use crate::papabearephem::{
    ciphertext_bytes as papabearephem_ciphertext_bytes, decapsulate as papabearephem_decapsulate,
    encapsulate as papabearephem_encapsulate, keypair as papabearephem_keypair,
    public_key_bytes as papabearephem_public_key_bytes,
    secret_key_bytes as papabearephem_secret_key_bytes,
    shared_secret_bytes as papabearephem_shared_secret_bytes,
};
