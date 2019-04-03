//! Kyber is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the
//! hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one
//! of the candidate algorithms submitted to the NIST post-quantum cryptography project. The
//! submission lists three different parameter sets aiming at different security levels.
//! Specifically, Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 aims at
//! security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to
//! AES-256.
//!
//! [https://pq-crystals.org/kyber/](https://pq-crystals.org/kyber/)

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
