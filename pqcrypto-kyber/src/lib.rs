//! # kyber
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * kyber512 - clean
//! * kyber768 - clean
//! * kyber1024 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

pub mod ffi;

pub mod kyber1024;
pub mod kyber512;
pub mod kyber768;

pub use crate::kyber1024::{
    ciphertext_bytes as kyber1024_ciphertext_bytes, decapsulate as kyber1024_decapsulate,
    encapsulate as kyber1024_encapsulate, keypair as kyber1024_keypair,
    public_key_bytes as kyber1024_public_key_bytes, secret_key_bytes as kyber1024_secret_key_bytes,
    shared_secret_bytes as kyber1024_shared_secret_bytes,
};
pub use crate::kyber512::{
    ciphertext_bytes as kyber512_ciphertext_bytes, decapsulate as kyber512_decapsulate,
    encapsulate as kyber512_encapsulate, keypair as kyber512_keypair,
    public_key_bytes as kyber512_public_key_bytes, secret_key_bytes as kyber512_secret_key_bytes,
    shared_secret_bytes as kyber512_shared_secret_bytes,
};
pub use crate::kyber768::{
    ciphertext_bytes as kyber768_ciphertext_bytes, decapsulate as kyber768_decapsulate,
    encapsulate as kyber768_encapsulate, keypair as kyber768_keypair,
    public_key_bytes as kyber768_public_key_bytes, secret_key_bytes as kyber768_secret_key_bytes,
    shared_secret_bytes as kyber768_shared_secret_bytes,
};
