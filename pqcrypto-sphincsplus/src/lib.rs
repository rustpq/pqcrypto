//! # sphincsplus
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * sphincs-shake-128f-simple - clean
//! * sphincs-shake-128s-simple - clean
//! * sphincs-shake-192f-simple - clean
//! * sphincs-shake-192s-simple - clean
//! * sphincs-shake-256f-simple - clean
//! * sphincs-shake-256s-simple - clean
//! * sphincs-sha2-128f-simple - clean
//! * sphincs-sha2-128s-simple - clean
//! * sphincs-sha2-192f-simple - clean
//! * sphincs-sha2-192s-simple - clean
//! * sphincs-sha2-256f-simple - clean
//! * sphincs-sha2-256s-simple - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

#![no_std]
#![allow(clippy::len_without_is_empty)]

// For no-std vectors
extern crate alloc;

// For tests
#[cfg(feature = "std")]
extern crate std;

pub mod ffi;
pub mod sphincssha2128fsimple;
pub mod sphincssha2128ssimple;
pub mod sphincssha2192fsimple;
pub mod sphincssha2192ssimple;
pub mod sphincssha2256fsimple;
pub mod sphincssha2256ssimple;
pub mod sphincsshake128fsimple;
pub mod sphincsshake128ssimple;
pub mod sphincsshake192fsimple;
pub mod sphincsshake192ssimple;
pub mod sphincsshake256fsimple;
pub mod sphincsshake256ssimple;

pub use crate::sphincssha2128fsimple::{
    detached_sign as sphincssha2128fsimple_detached_sign, keypair as sphincssha2128fsimple_keypair,
    open as sphincssha2128fsimple_open, public_key_bytes as sphincssha2128fsimple_public_key_bytes,
    secret_key_bytes as sphincssha2128fsimple_secret_key_bytes, sign as sphincssha2128fsimple_sign,
    signature_bytes as sphincssha2128fsimple_signature_bytes,
    verify_detached_signature as sphincssha2128fsimple_verify_detached_signature,
};
pub use crate::sphincssha2128ssimple::{
    detached_sign as sphincssha2128ssimple_detached_sign, keypair as sphincssha2128ssimple_keypair,
    open as sphincssha2128ssimple_open, public_key_bytes as sphincssha2128ssimple_public_key_bytes,
    secret_key_bytes as sphincssha2128ssimple_secret_key_bytes, sign as sphincssha2128ssimple_sign,
    signature_bytes as sphincssha2128ssimple_signature_bytes,
    verify_detached_signature as sphincssha2128ssimple_verify_detached_signature,
};
pub use crate::sphincssha2192fsimple::{
    detached_sign as sphincssha2192fsimple_detached_sign, keypair as sphincssha2192fsimple_keypair,
    open as sphincssha2192fsimple_open, public_key_bytes as sphincssha2192fsimple_public_key_bytes,
    secret_key_bytes as sphincssha2192fsimple_secret_key_bytes, sign as sphincssha2192fsimple_sign,
    signature_bytes as sphincssha2192fsimple_signature_bytes,
    verify_detached_signature as sphincssha2192fsimple_verify_detached_signature,
};
pub use crate::sphincssha2192ssimple::{
    detached_sign as sphincssha2192ssimple_detached_sign, keypair as sphincssha2192ssimple_keypair,
    open as sphincssha2192ssimple_open, public_key_bytes as sphincssha2192ssimple_public_key_bytes,
    secret_key_bytes as sphincssha2192ssimple_secret_key_bytes, sign as sphincssha2192ssimple_sign,
    signature_bytes as sphincssha2192ssimple_signature_bytes,
    verify_detached_signature as sphincssha2192ssimple_verify_detached_signature,
};
pub use crate::sphincssha2256fsimple::{
    detached_sign as sphincssha2256fsimple_detached_sign, keypair as sphincssha2256fsimple_keypair,
    open as sphincssha2256fsimple_open, public_key_bytes as sphincssha2256fsimple_public_key_bytes,
    secret_key_bytes as sphincssha2256fsimple_secret_key_bytes, sign as sphincssha2256fsimple_sign,
    signature_bytes as sphincssha2256fsimple_signature_bytes,
    verify_detached_signature as sphincssha2256fsimple_verify_detached_signature,
};
pub use crate::sphincssha2256ssimple::{
    detached_sign as sphincssha2256ssimple_detached_sign, keypair as sphincssha2256ssimple_keypair,
    open as sphincssha2256ssimple_open, public_key_bytes as sphincssha2256ssimple_public_key_bytes,
    secret_key_bytes as sphincssha2256ssimple_secret_key_bytes, sign as sphincssha2256ssimple_sign,
    signature_bytes as sphincssha2256ssimple_signature_bytes,
    verify_detached_signature as sphincssha2256ssimple_verify_detached_signature,
};
pub use crate::sphincsshake128fsimple::{
    detached_sign as sphincsshake128fsimple_detached_sign,
    keypair as sphincsshake128fsimple_keypair, open as sphincsshake128fsimple_open,
    public_key_bytes as sphincsshake128fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake128fsimple_secret_key_bytes,
    sign as sphincsshake128fsimple_sign, signature_bytes as sphincsshake128fsimple_signature_bytes,
    verify_detached_signature as sphincsshake128fsimple_verify_detached_signature,
};
pub use crate::sphincsshake128ssimple::{
    detached_sign as sphincsshake128ssimple_detached_sign,
    keypair as sphincsshake128ssimple_keypair, open as sphincsshake128ssimple_open,
    public_key_bytes as sphincsshake128ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake128ssimple_secret_key_bytes,
    sign as sphincsshake128ssimple_sign, signature_bytes as sphincsshake128ssimple_signature_bytes,
    verify_detached_signature as sphincsshake128ssimple_verify_detached_signature,
};
pub use crate::sphincsshake192fsimple::{
    detached_sign as sphincsshake192fsimple_detached_sign,
    keypair as sphincsshake192fsimple_keypair, open as sphincsshake192fsimple_open,
    public_key_bytes as sphincsshake192fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake192fsimple_secret_key_bytes,
    sign as sphincsshake192fsimple_sign, signature_bytes as sphincsshake192fsimple_signature_bytes,
    verify_detached_signature as sphincsshake192fsimple_verify_detached_signature,
};
pub use crate::sphincsshake192ssimple::{
    detached_sign as sphincsshake192ssimple_detached_sign,
    keypair as sphincsshake192ssimple_keypair, open as sphincsshake192ssimple_open,
    public_key_bytes as sphincsshake192ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake192ssimple_secret_key_bytes,
    sign as sphincsshake192ssimple_sign, signature_bytes as sphincsshake192ssimple_signature_bytes,
    verify_detached_signature as sphincsshake192ssimple_verify_detached_signature,
};
pub use crate::sphincsshake256fsimple::{
    detached_sign as sphincsshake256fsimple_detached_sign,
    keypair as sphincsshake256fsimple_keypair, open as sphincsshake256fsimple_open,
    public_key_bytes as sphincsshake256fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake256fsimple_secret_key_bytes,
    sign as sphincsshake256fsimple_sign, signature_bytes as sphincsshake256fsimple_signature_bytes,
    verify_detached_signature as sphincsshake256fsimple_verify_detached_signature,
};
pub use crate::sphincsshake256ssimple::{
    detached_sign as sphincsshake256ssimple_detached_sign,
    keypair as sphincsshake256ssimple_keypair, open as sphincsshake256ssimple_open,
    public_key_bytes as sphincsshake256ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake256ssimple_secret_key_bytes,
    sign as sphincsshake256ssimple_sign, signature_bytes as sphincsshake256ssimple_signature_bytes,
    verify_detached_signature as sphincsshake256ssimple_verify_detached_signature,
};
