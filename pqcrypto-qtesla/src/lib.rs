//! # qtesla
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * qtesla-p-I - clean
//! * qtesla-p-III - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![allow(clippy::len_without_is_empty)]

pub mod ffi;
pub mod qteslapi;
pub mod qteslapiii;

pub use crate::qteslapi::{
    detached_sign as qteslapi_detached_sign, keypair as qteslapi_keypair, open as qteslapi_open,
    public_key_bytes as qteslapi_public_key_bytes, secret_key_bytes as qteslapi_secret_key_bytes,
    sign as qteslapi_sign, signature_bytes as qteslapi_signature_bytes,
    verify_detached_signature as qteslapi_verify_detached_signature,
};
pub use crate::qteslapiii::{
    detached_sign as qteslapiii_detached_sign, keypair as qteslapiii_keypair,
    open as qteslapiii_open, public_key_bytes as qteslapiii_public_key_bytes,
    secret_key_bytes as qteslapiii_secret_key_bytes, sign as qteslapiii_sign,
    signature_bytes as qteslapiii_signature_bytes,
    verify_detached_signature as qteslapiii_verify_detached_signature,
};
