//! # newhope
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * newhope1024cpa - clean
//! * newhope1024cca - clean
//! * newhope512cpa - clean
//! * newhope512cca - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod ffi;
pub mod newhope1024cca;
pub mod newhope1024cpa;
pub mod newhope512cca;
pub mod newhope512cpa;

pub use crate::newhope1024cca::{
    ciphertext_bytes as newhope1024cca_ciphertext_bytes, decapsulate as newhope1024cca_decapsulate,
    encapsulate as newhope1024cca_encapsulate, keypair as newhope1024cca_keypair,
    public_key_bytes as newhope1024cca_public_key_bytes,
    secret_key_bytes as newhope1024cca_secret_key_bytes,
    shared_secret_bytes as newhope1024cca_shared_secret_bytes,
};
pub use crate::newhope1024cpa::{
    ciphertext_bytes as newhope1024cpa_ciphertext_bytes, decapsulate as newhope1024cpa_decapsulate,
    encapsulate as newhope1024cpa_encapsulate, keypair as newhope1024cpa_keypair,
    public_key_bytes as newhope1024cpa_public_key_bytes,
    secret_key_bytes as newhope1024cpa_secret_key_bytes,
    shared_secret_bytes as newhope1024cpa_shared_secret_bytes,
};
pub use crate::newhope512cca::{
    ciphertext_bytes as newhope512cca_ciphertext_bytes, decapsulate as newhope512cca_decapsulate,
    encapsulate as newhope512cca_encapsulate, keypair as newhope512cca_keypair,
    public_key_bytes as newhope512cca_public_key_bytes,
    secret_key_bytes as newhope512cca_secret_key_bytes,
    shared_secret_bytes as newhope512cca_shared_secret_bytes,
};
pub use crate::newhope512cpa::{
    ciphertext_bytes as newhope512cpa_ciphertext_bytes, decapsulate as newhope512cpa_decapsulate,
    encapsulate as newhope512cpa_encapsulate, keypair as newhope512cpa_keypair,
    public_key_bytes as newhope512cpa_public_key_bytes,
    secret_key_bytes as newhope512cpa_secret_key_bytes,
    shared_secret_bytes as newhope512cpa_shared_secret_bytes,
};
