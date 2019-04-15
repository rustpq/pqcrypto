//! # kyber
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * kyber768 - clean

//!
//! [pqc]: https://github.com/pqclean/pqclean/

pub mod ffi;


pub mod kyber768;



pub use crate::kyber768::{
    encapsulate as kyber768_encapsulate,
    decapsulate as kyber768_decapsulate,
    keypair as kyber768_keypair,
    public_key_bytes as kyber768_public_key_bytes,
    secret_key_bytes as kyber768_secret_key_bytes,
    ciphertext_bytes as kyber768_ciphertext_bytes,
    shared_secret_bytes as kyber768_shared_secret_bytes,
};
