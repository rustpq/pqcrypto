//! # frodo
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * frodokem640aes - opt
//! * frodokem640shake - opt
//! * frodokem976aes - opt
//! * frodokem976shake - opt
//! * frodokem1344aes - opt
//! * frodokem1344shake - opt
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!
//! # Notes
//! If you use it via the FFI interface: The ``clean`` implementation of
//! Frodo needs a lot of stack space, specify env variable
//! `RUST_MIN_STACK` to make sure it has enough stack space in threads.
//! This is not relevant for the 'normal' api methods.

#![allow(clippy::len_without_is_empty)]

pub mod ffi;
pub mod frodokem1344aes;
pub mod frodokem1344shake;
pub mod frodokem640aes;
pub mod frodokem640shake;
pub mod frodokem976aes;
pub mod frodokem976shake;

pub use crate::frodokem1344aes::{
    ciphertext_bytes as frodokem1344aes_ciphertext_bytes,
    decapsulate as frodokem1344aes_decapsulate, encapsulate as frodokem1344aes_encapsulate,
    keypair as frodokem1344aes_keypair, public_key_bytes as frodokem1344aes_public_key_bytes,
    secret_key_bytes as frodokem1344aes_secret_key_bytes,
    shared_secret_bytes as frodokem1344aes_shared_secret_bytes,
};
pub use crate::frodokem1344shake::{
    ciphertext_bytes as frodokem1344shake_ciphertext_bytes,
    decapsulate as frodokem1344shake_decapsulate, encapsulate as frodokem1344shake_encapsulate,
    keypair as frodokem1344shake_keypair, public_key_bytes as frodokem1344shake_public_key_bytes,
    secret_key_bytes as frodokem1344shake_secret_key_bytes,
    shared_secret_bytes as frodokem1344shake_shared_secret_bytes,
};
pub use crate::frodokem640aes::{
    ciphertext_bytes as frodokem640aes_ciphertext_bytes, decapsulate as frodokem640aes_decapsulate,
    encapsulate as frodokem640aes_encapsulate, keypair as frodokem640aes_keypair,
    public_key_bytes as frodokem640aes_public_key_bytes,
    secret_key_bytes as frodokem640aes_secret_key_bytes,
    shared_secret_bytes as frodokem640aes_shared_secret_bytes,
};
pub use crate::frodokem640shake::{
    ciphertext_bytes as frodokem640shake_ciphertext_bytes,
    decapsulate as frodokem640shake_decapsulate, encapsulate as frodokem640shake_encapsulate,
    keypair as frodokem640shake_keypair, public_key_bytes as frodokem640shake_public_key_bytes,
    secret_key_bytes as frodokem640shake_secret_key_bytes,
    shared_secret_bytes as frodokem640shake_shared_secret_bytes,
};
pub use crate::frodokem976aes::{
    ciphertext_bytes as frodokem976aes_ciphertext_bytes, decapsulate as frodokem976aes_decapsulate,
    encapsulate as frodokem976aes_encapsulate, keypair as frodokem976aes_keypair,
    public_key_bytes as frodokem976aes_public_key_bytes,
    secret_key_bytes as frodokem976aes_secret_key_bytes,
    shared_secret_bytes as frodokem976aes_shared_secret_bytes,
};
pub use crate::frodokem976shake::{
    ciphertext_bytes as frodokem976shake_ciphertext_bytes,
    decapsulate as frodokem976shake_decapsulate, encapsulate as frodokem976shake_encapsulate,
    keypair as frodokem976shake_keypair, public_key_bytes as frodokem976shake_public_key_bytes,
    secret_key_bytes as frodokem976shake_secret_key_bytes,
    shared_secret_bytes as frodokem976shake_shared_secret_bytes,
};
