//! # frodo
//! 
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * frodokem640shake - clean
//! * frodokem1344shake - clean

//!
//! [pqc]: https://github.com/pqclean/pqclean/

pub mod ffi;


pub mod frodokem640shake;

pub mod frodokem1344shake;



pub use crate::frodokem640shake::{
    encapsulate as frodokem640shake_encapsulate,
    decapsulate as frodokem640shake_decapsulate,
    keypair as frodokem640shake_keypair,
    public_key_bytes as frodokem640shake_public_key_bytes,
    secret_key_bytes as frodokem640shake_secret_key_bytes,
    ciphertext_bytes as frodokem640shake_ciphertext_bytes,
    shared_secret_bytes as frodokem640shake_shared_secret_bytes,
};


pub use crate::frodokem1344shake::{
    encapsulate as frodokem1344shake_encapsulate,
    decapsulate as frodokem1344shake_decapsulate,
    keypair as frodokem1344shake_keypair,
    public_key_bytes as frodokem1344shake_public_key_bytes,
    secret_key_bytes as frodokem1344shake_secret_key_bytes,
    ciphertext_bytes as frodokem1344shake_ciphertext_bytes,
    shared_secret_bytes as frodokem1344shake_shared_secret_bytes,
};

