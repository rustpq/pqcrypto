//! # frodo
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * frodokem640shake - clean
//! * frodokem976aes - clean
//! * frodokem976shake - clean
//! * frodokem1344aes - clean
//! * frodokem1344shake - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!
//! # Notes
//! Frodo needs a lot of stack space, specify env variable
//! `RUST_MIN_STACK` to make sure it has enough stack space in threads.

pub mod ffi;

pub mod frodokem640shake;
pub mod frodokem976aes;
pub mod frodokem976shake;
pub mod frodokem1344aes;
pub mod frodokem1344shake;

pub use crate::frodokem640shake::{
    keypair as frodokem640shake_keypair,
    public_key_bytes as frodokem640shake_public_key_bytes,
    secret_key_bytes as frodokem640shake_secret_key_bytes,
    encapsulate as frodokem640shake_encapsulate,
    decapsulate as frodokem640shake_decapsulate,
    ciphertext_bytes as frodokem640shake_ciphertext_bytes,
    shared_secret_bytes as frodokem640shake_shared_secret_bytes,
};
pub use crate::frodokem976aes::{
    keypair as frodokem976aes_keypair,
    public_key_bytes as frodokem976aes_public_key_bytes,
    secret_key_bytes as frodokem976aes_secret_key_bytes,
    encapsulate as frodokem976aes_encapsulate,
    decapsulate as frodokem976aes_decapsulate,
    ciphertext_bytes as frodokem976aes_ciphertext_bytes,
    shared_secret_bytes as frodokem976aes_shared_secret_bytes,
};
pub use crate::frodokem976shake::{
    keypair as frodokem976shake_keypair,
    public_key_bytes as frodokem976shake_public_key_bytes,
    secret_key_bytes as frodokem976shake_secret_key_bytes,
    encapsulate as frodokem976shake_encapsulate,
    decapsulate as frodokem976shake_decapsulate,
    ciphertext_bytes as frodokem976shake_ciphertext_bytes,
    shared_secret_bytes as frodokem976shake_shared_secret_bytes,
};
pub use crate::frodokem1344aes::{
    keypair as frodokem1344aes_keypair,
    public_key_bytes as frodokem1344aes_public_key_bytes,
    secret_key_bytes as frodokem1344aes_secret_key_bytes,
    encapsulate as frodokem1344aes_encapsulate,
    decapsulate as frodokem1344aes_decapsulate,
    ciphertext_bytes as frodokem1344aes_ciphertext_bytes,
    shared_secret_bytes as frodokem1344aes_shared_secret_bytes,
};
pub use crate::frodokem1344shake::{
    keypair as frodokem1344shake_keypair,
    public_key_bytes as frodokem1344shake_public_key_bytes,
    secret_key_bytes as frodokem1344shake_secret_key_bytes,
    encapsulate as frodokem1344shake_encapsulate,
    decapsulate as frodokem1344shake_decapsulate,
    ciphertext_bytes as frodokem1344shake_ciphertext_bytes,
    shared_secret_bytes as frodokem1344shake_shared_secret_bytes,
};
