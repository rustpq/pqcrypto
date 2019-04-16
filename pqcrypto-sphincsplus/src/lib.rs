//! # sphincsplus
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * sphincs-shake256-128f-simple - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

pub mod ffi;

pub mod sphincsshake256128fsimple;

pub use crate::sphincsshake256128fsimple::{
    keypair as sphincsshake256128fsimple_keypair,
    public_key_bytes as sphincsshake256128fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake256128fsimple_secret_key_bytes,
    signature_bytes as sphincsshake256128fsimple_signature_bytes,
};
