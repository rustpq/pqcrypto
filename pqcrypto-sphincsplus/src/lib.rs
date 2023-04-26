//! # sphincsplus
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * sphincs-haraka-128f-robust - clean
//! * sphincs-haraka-128f-simple - clean
//! * sphincs-haraka-128s-robust - clean
//! * sphincs-haraka-128s-simple - clean
//! * sphincs-haraka-192f-robust - clean
//! * sphincs-haraka-192f-simple - clean
//! * sphincs-haraka-192s-robust - clean
//! * sphincs-haraka-192s-simple - clean
//! * sphincs-haraka-256f-robust - clean
//! * sphincs-haraka-256f-simple - clean
//! * sphincs-haraka-256s-robust - clean
//! * sphincs-haraka-256s-simple - clean
//! * sphincs-shake-128f-robust - clean
//! * sphincs-shake-128f-simple - clean
//! * sphincs-shake-128s-robust - clean
//! * sphincs-shake-128s-simple - clean
//! * sphincs-shake-192f-robust - clean
//! * sphincs-shake-192f-simple - clean
//! * sphincs-shake-192s-robust - clean
//! * sphincs-shake-192s-simple - clean
//! * sphincs-shake-256f-robust - clean
//! * sphincs-shake-256f-simple - clean
//! * sphincs-shake-256s-robust - clean
//! * sphincs-shake-256s-simple - clean
//! * sphincs-sha2-128f-robust - clean
//! * sphincs-sha2-128f-simple - clean
//! * sphincs-sha2-128s-robust - clean
//! * sphincs-sha2-128s-simple - clean
//! * sphincs-sha2-192f-robust - clean
//! * sphincs-sha2-192f-simple - clean
//! * sphincs-sha2-192s-robust - clean
//! * sphincs-sha2-192s-simple - clean
//! * sphincs-sha2-256f-robust - clean
//! * sphincs-sha2-256f-simple - clean
//! * sphincs-sha2-256s-robust - clean
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
pub mod sphincsharaka128frobust;
pub mod sphincsharaka128fsimple;
pub mod sphincsharaka128srobust;
pub mod sphincsharaka128ssimple;
pub mod sphincsharaka192frobust;
pub mod sphincsharaka192fsimple;
pub mod sphincsharaka192srobust;
pub mod sphincsharaka192ssimple;
pub mod sphincsharaka256frobust;
pub mod sphincsharaka256fsimple;
pub mod sphincsharaka256srobust;
pub mod sphincsharaka256ssimple;
pub mod sphincssha2128frobust;
pub mod sphincssha2128fsimple;
pub mod sphincssha2128srobust;
pub mod sphincssha2128ssimple;
pub mod sphincssha2192frobust;
pub mod sphincssha2192fsimple;
pub mod sphincssha2192srobust;
pub mod sphincssha2192ssimple;
pub mod sphincssha2256frobust;
pub mod sphincssha2256fsimple;
pub mod sphincssha2256srobust;
pub mod sphincssha2256ssimple;
pub mod sphincsshake128frobust;
pub mod sphincsshake128fsimple;
pub mod sphincsshake128srobust;
pub mod sphincsshake128ssimple;
pub mod sphincsshake192frobust;
pub mod sphincsshake192fsimple;
pub mod sphincsshake192srobust;
pub mod sphincsshake192ssimple;
pub mod sphincsshake256frobust;
pub mod sphincsshake256fsimple;
pub mod sphincsshake256srobust;
pub mod sphincsshake256ssimple;

pub use crate::sphincsharaka128frobust::{
    detached_sign as sphincsharaka128frobust_detached_sign,
    keypair as sphincsharaka128frobust_keypair, open as sphincsharaka128frobust_open,
    public_key_bytes as sphincsharaka128frobust_public_key_bytes,
    secret_key_bytes as sphincsharaka128frobust_secret_key_bytes,
    sign as sphincsharaka128frobust_sign,
    signature_bytes as sphincsharaka128frobust_signature_bytes,
    verify_detached_signature as sphincsharaka128frobust_verify_detached_signature,
};
pub use crate::sphincsharaka128fsimple::{
    detached_sign as sphincsharaka128fsimple_detached_sign,
    keypair as sphincsharaka128fsimple_keypair, open as sphincsharaka128fsimple_open,
    public_key_bytes as sphincsharaka128fsimple_public_key_bytes,
    secret_key_bytes as sphincsharaka128fsimple_secret_key_bytes,
    sign as sphincsharaka128fsimple_sign,
    signature_bytes as sphincsharaka128fsimple_signature_bytes,
    verify_detached_signature as sphincsharaka128fsimple_verify_detached_signature,
};
pub use crate::sphincsharaka128srobust::{
    detached_sign as sphincsharaka128srobust_detached_sign,
    keypair as sphincsharaka128srobust_keypair, open as sphincsharaka128srobust_open,
    public_key_bytes as sphincsharaka128srobust_public_key_bytes,
    secret_key_bytes as sphincsharaka128srobust_secret_key_bytes,
    sign as sphincsharaka128srobust_sign,
    signature_bytes as sphincsharaka128srobust_signature_bytes,
    verify_detached_signature as sphincsharaka128srobust_verify_detached_signature,
};
pub use crate::sphincsharaka128ssimple::{
    detached_sign as sphincsharaka128ssimple_detached_sign,
    keypair as sphincsharaka128ssimple_keypair, open as sphincsharaka128ssimple_open,
    public_key_bytes as sphincsharaka128ssimple_public_key_bytes,
    secret_key_bytes as sphincsharaka128ssimple_secret_key_bytes,
    sign as sphincsharaka128ssimple_sign,
    signature_bytes as sphincsharaka128ssimple_signature_bytes,
    verify_detached_signature as sphincsharaka128ssimple_verify_detached_signature,
};
pub use crate::sphincsharaka192frobust::{
    detached_sign as sphincsharaka192frobust_detached_sign,
    keypair as sphincsharaka192frobust_keypair, open as sphincsharaka192frobust_open,
    public_key_bytes as sphincsharaka192frobust_public_key_bytes,
    secret_key_bytes as sphincsharaka192frobust_secret_key_bytes,
    sign as sphincsharaka192frobust_sign,
    signature_bytes as sphincsharaka192frobust_signature_bytes,
    verify_detached_signature as sphincsharaka192frobust_verify_detached_signature,
};
pub use crate::sphincsharaka192fsimple::{
    detached_sign as sphincsharaka192fsimple_detached_sign,
    keypair as sphincsharaka192fsimple_keypair, open as sphincsharaka192fsimple_open,
    public_key_bytes as sphincsharaka192fsimple_public_key_bytes,
    secret_key_bytes as sphincsharaka192fsimple_secret_key_bytes,
    sign as sphincsharaka192fsimple_sign,
    signature_bytes as sphincsharaka192fsimple_signature_bytes,
    verify_detached_signature as sphincsharaka192fsimple_verify_detached_signature,
};
pub use crate::sphincsharaka192srobust::{
    detached_sign as sphincsharaka192srobust_detached_sign,
    keypair as sphincsharaka192srobust_keypair, open as sphincsharaka192srobust_open,
    public_key_bytes as sphincsharaka192srobust_public_key_bytes,
    secret_key_bytes as sphincsharaka192srobust_secret_key_bytes,
    sign as sphincsharaka192srobust_sign,
    signature_bytes as sphincsharaka192srobust_signature_bytes,
    verify_detached_signature as sphincsharaka192srobust_verify_detached_signature,
};
pub use crate::sphincsharaka192ssimple::{
    detached_sign as sphincsharaka192ssimple_detached_sign,
    keypair as sphincsharaka192ssimple_keypair, open as sphincsharaka192ssimple_open,
    public_key_bytes as sphincsharaka192ssimple_public_key_bytes,
    secret_key_bytes as sphincsharaka192ssimple_secret_key_bytes,
    sign as sphincsharaka192ssimple_sign,
    signature_bytes as sphincsharaka192ssimple_signature_bytes,
    verify_detached_signature as sphincsharaka192ssimple_verify_detached_signature,
};
pub use crate::sphincsharaka256frobust::{
    detached_sign as sphincsharaka256frobust_detached_sign,
    keypair as sphincsharaka256frobust_keypair, open as sphincsharaka256frobust_open,
    public_key_bytes as sphincsharaka256frobust_public_key_bytes,
    secret_key_bytes as sphincsharaka256frobust_secret_key_bytes,
    sign as sphincsharaka256frobust_sign,
    signature_bytes as sphincsharaka256frobust_signature_bytes,
    verify_detached_signature as sphincsharaka256frobust_verify_detached_signature,
};
pub use crate::sphincsharaka256fsimple::{
    detached_sign as sphincsharaka256fsimple_detached_sign,
    keypair as sphincsharaka256fsimple_keypair, open as sphincsharaka256fsimple_open,
    public_key_bytes as sphincsharaka256fsimple_public_key_bytes,
    secret_key_bytes as sphincsharaka256fsimple_secret_key_bytes,
    sign as sphincsharaka256fsimple_sign,
    signature_bytes as sphincsharaka256fsimple_signature_bytes,
    verify_detached_signature as sphincsharaka256fsimple_verify_detached_signature,
};
pub use crate::sphincsharaka256srobust::{
    detached_sign as sphincsharaka256srobust_detached_sign,
    keypair as sphincsharaka256srobust_keypair, open as sphincsharaka256srobust_open,
    public_key_bytes as sphincsharaka256srobust_public_key_bytes,
    secret_key_bytes as sphincsharaka256srobust_secret_key_bytes,
    sign as sphincsharaka256srobust_sign,
    signature_bytes as sphincsharaka256srobust_signature_bytes,
    verify_detached_signature as sphincsharaka256srobust_verify_detached_signature,
};
pub use crate::sphincsharaka256ssimple::{
    detached_sign as sphincsharaka256ssimple_detached_sign,
    keypair as sphincsharaka256ssimple_keypair, open as sphincsharaka256ssimple_open,
    public_key_bytes as sphincsharaka256ssimple_public_key_bytes,
    secret_key_bytes as sphincsharaka256ssimple_secret_key_bytes,
    sign as sphincsharaka256ssimple_sign,
    signature_bytes as sphincsharaka256ssimple_signature_bytes,
    verify_detached_signature as sphincsharaka256ssimple_verify_detached_signature,
};
pub use crate::sphincssha2128frobust::{
    detached_sign as sphincssha2128frobust_detached_sign, keypair as sphincssha2128frobust_keypair,
    open as sphincssha2128frobust_open, public_key_bytes as sphincssha2128frobust_public_key_bytes,
    secret_key_bytes as sphincssha2128frobust_secret_key_bytes, sign as sphincssha2128frobust_sign,
    signature_bytes as sphincssha2128frobust_signature_bytes,
    verify_detached_signature as sphincssha2128frobust_verify_detached_signature,
};
pub use crate::sphincssha2128fsimple::{
    detached_sign as sphincssha2128fsimple_detached_sign, keypair as sphincssha2128fsimple_keypair,
    open as sphincssha2128fsimple_open, public_key_bytes as sphincssha2128fsimple_public_key_bytes,
    secret_key_bytes as sphincssha2128fsimple_secret_key_bytes, sign as sphincssha2128fsimple_sign,
    signature_bytes as sphincssha2128fsimple_signature_bytes,
    verify_detached_signature as sphincssha2128fsimple_verify_detached_signature,
};
pub use crate::sphincssha2128srobust::{
    detached_sign as sphincssha2128srobust_detached_sign, keypair as sphincssha2128srobust_keypair,
    open as sphincssha2128srobust_open, public_key_bytes as sphincssha2128srobust_public_key_bytes,
    secret_key_bytes as sphincssha2128srobust_secret_key_bytes, sign as sphincssha2128srobust_sign,
    signature_bytes as sphincssha2128srobust_signature_bytes,
    verify_detached_signature as sphincssha2128srobust_verify_detached_signature,
};
pub use crate::sphincssha2128ssimple::{
    detached_sign as sphincssha2128ssimple_detached_sign, keypair as sphincssha2128ssimple_keypair,
    open as sphincssha2128ssimple_open, public_key_bytes as sphincssha2128ssimple_public_key_bytes,
    secret_key_bytes as sphincssha2128ssimple_secret_key_bytes, sign as sphincssha2128ssimple_sign,
    signature_bytes as sphincssha2128ssimple_signature_bytes,
    verify_detached_signature as sphincssha2128ssimple_verify_detached_signature,
};
pub use crate::sphincssha2192frobust::{
    detached_sign as sphincssha2192frobust_detached_sign, keypair as sphincssha2192frobust_keypair,
    open as sphincssha2192frobust_open, public_key_bytes as sphincssha2192frobust_public_key_bytes,
    secret_key_bytes as sphincssha2192frobust_secret_key_bytes, sign as sphincssha2192frobust_sign,
    signature_bytes as sphincssha2192frobust_signature_bytes,
    verify_detached_signature as sphincssha2192frobust_verify_detached_signature,
};
pub use crate::sphincssha2192fsimple::{
    detached_sign as sphincssha2192fsimple_detached_sign, keypair as sphincssha2192fsimple_keypair,
    open as sphincssha2192fsimple_open, public_key_bytes as sphincssha2192fsimple_public_key_bytes,
    secret_key_bytes as sphincssha2192fsimple_secret_key_bytes, sign as sphincssha2192fsimple_sign,
    signature_bytes as sphincssha2192fsimple_signature_bytes,
    verify_detached_signature as sphincssha2192fsimple_verify_detached_signature,
};
pub use crate::sphincssha2192srobust::{
    detached_sign as sphincssha2192srobust_detached_sign, keypair as sphincssha2192srobust_keypair,
    open as sphincssha2192srobust_open, public_key_bytes as sphincssha2192srobust_public_key_bytes,
    secret_key_bytes as sphincssha2192srobust_secret_key_bytes, sign as sphincssha2192srobust_sign,
    signature_bytes as sphincssha2192srobust_signature_bytes,
    verify_detached_signature as sphincssha2192srobust_verify_detached_signature,
};
pub use crate::sphincssha2192ssimple::{
    detached_sign as sphincssha2192ssimple_detached_sign, keypair as sphincssha2192ssimple_keypair,
    open as sphincssha2192ssimple_open, public_key_bytes as sphincssha2192ssimple_public_key_bytes,
    secret_key_bytes as sphincssha2192ssimple_secret_key_bytes, sign as sphincssha2192ssimple_sign,
    signature_bytes as sphincssha2192ssimple_signature_bytes,
    verify_detached_signature as sphincssha2192ssimple_verify_detached_signature,
};
pub use crate::sphincssha2256frobust::{
    detached_sign as sphincssha2256frobust_detached_sign, keypair as sphincssha2256frobust_keypair,
    open as sphincssha2256frobust_open, public_key_bytes as sphincssha2256frobust_public_key_bytes,
    secret_key_bytes as sphincssha2256frobust_secret_key_bytes, sign as sphincssha2256frobust_sign,
    signature_bytes as sphincssha2256frobust_signature_bytes,
    verify_detached_signature as sphincssha2256frobust_verify_detached_signature,
};
pub use crate::sphincssha2256fsimple::{
    detached_sign as sphincssha2256fsimple_detached_sign, keypair as sphincssha2256fsimple_keypair,
    open as sphincssha2256fsimple_open, public_key_bytes as sphincssha2256fsimple_public_key_bytes,
    secret_key_bytes as sphincssha2256fsimple_secret_key_bytes, sign as sphincssha2256fsimple_sign,
    signature_bytes as sphincssha2256fsimple_signature_bytes,
    verify_detached_signature as sphincssha2256fsimple_verify_detached_signature,
};
pub use crate::sphincssha2256srobust::{
    detached_sign as sphincssha2256srobust_detached_sign, keypair as sphincssha2256srobust_keypair,
    open as sphincssha2256srobust_open, public_key_bytes as sphincssha2256srobust_public_key_bytes,
    secret_key_bytes as sphincssha2256srobust_secret_key_bytes, sign as sphincssha2256srobust_sign,
    signature_bytes as sphincssha2256srobust_signature_bytes,
    verify_detached_signature as sphincssha2256srobust_verify_detached_signature,
};
pub use crate::sphincssha2256ssimple::{
    detached_sign as sphincssha2256ssimple_detached_sign, keypair as sphincssha2256ssimple_keypair,
    open as sphincssha2256ssimple_open, public_key_bytes as sphincssha2256ssimple_public_key_bytes,
    secret_key_bytes as sphincssha2256ssimple_secret_key_bytes, sign as sphincssha2256ssimple_sign,
    signature_bytes as sphincssha2256ssimple_signature_bytes,
    verify_detached_signature as sphincssha2256ssimple_verify_detached_signature,
};
pub use crate::sphincsshake128frobust::{
    detached_sign as sphincsshake128frobust_detached_sign,
    keypair as sphincsshake128frobust_keypair, open as sphincsshake128frobust_open,
    public_key_bytes as sphincsshake128frobust_public_key_bytes,
    secret_key_bytes as sphincsshake128frobust_secret_key_bytes,
    sign as sphincsshake128frobust_sign, signature_bytes as sphincsshake128frobust_signature_bytes,
    verify_detached_signature as sphincsshake128frobust_verify_detached_signature,
};
pub use crate::sphincsshake128fsimple::{
    detached_sign as sphincsshake128fsimple_detached_sign,
    keypair as sphincsshake128fsimple_keypair, open as sphincsshake128fsimple_open,
    public_key_bytes as sphincsshake128fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake128fsimple_secret_key_bytes,
    sign as sphincsshake128fsimple_sign, signature_bytes as sphincsshake128fsimple_signature_bytes,
    verify_detached_signature as sphincsshake128fsimple_verify_detached_signature,
};
pub use crate::sphincsshake128srobust::{
    detached_sign as sphincsshake128srobust_detached_sign,
    keypair as sphincsshake128srobust_keypair, open as sphincsshake128srobust_open,
    public_key_bytes as sphincsshake128srobust_public_key_bytes,
    secret_key_bytes as sphincsshake128srobust_secret_key_bytes,
    sign as sphincsshake128srobust_sign, signature_bytes as sphincsshake128srobust_signature_bytes,
    verify_detached_signature as sphincsshake128srobust_verify_detached_signature,
};
pub use crate::sphincsshake128ssimple::{
    detached_sign as sphincsshake128ssimple_detached_sign,
    keypair as sphincsshake128ssimple_keypair, open as sphincsshake128ssimple_open,
    public_key_bytes as sphincsshake128ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake128ssimple_secret_key_bytes,
    sign as sphincsshake128ssimple_sign, signature_bytes as sphincsshake128ssimple_signature_bytes,
    verify_detached_signature as sphincsshake128ssimple_verify_detached_signature,
};
pub use crate::sphincsshake192frobust::{
    detached_sign as sphincsshake192frobust_detached_sign,
    keypair as sphincsshake192frobust_keypair, open as sphincsshake192frobust_open,
    public_key_bytes as sphincsshake192frobust_public_key_bytes,
    secret_key_bytes as sphincsshake192frobust_secret_key_bytes,
    sign as sphincsshake192frobust_sign, signature_bytes as sphincsshake192frobust_signature_bytes,
    verify_detached_signature as sphincsshake192frobust_verify_detached_signature,
};
pub use crate::sphincsshake192fsimple::{
    detached_sign as sphincsshake192fsimple_detached_sign,
    keypair as sphincsshake192fsimple_keypair, open as sphincsshake192fsimple_open,
    public_key_bytes as sphincsshake192fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake192fsimple_secret_key_bytes,
    sign as sphincsshake192fsimple_sign, signature_bytes as sphincsshake192fsimple_signature_bytes,
    verify_detached_signature as sphincsshake192fsimple_verify_detached_signature,
};
pub use crate::sphincsshake192srobust::{
    detached_sign as sphincsshake192srobust_detached_sign,
    keypair as sphincsshake192srobust_keypair, open as sphincsshake192srobust_open,
    public_key_bytes as sphincsshake192srobust_public_key_bytes,
    secret_key_bytes as sphincsshake192srobust_secret_key_bytes,
    sign as sphincsshake192srobust_sign, signature_bytes as sphincsshake192srobust_signature_bytes,
    verify_detached_signature as sphincsshake192srobust_verify_detached_signature,
};
pub use crate::sphincsshake192ssimple::{
    detached_sign as sphincsshake192ssimple_detached_sign,
    keypair as sphincsshake192ssimple_keypair, open as sphincsshake192ssimple_open,
    public_key_bytes as sphincsshake192ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake192ssimple_secret_key_bytes,
    sign as sphincsshake192ssimple_sign, signature_bytes as sphincsshake192ssimple_signature_bytes,
    verify_detached_signature as sphincsshake192ssimple_verify_detached_signature,
};
pub use crate::sphincsshake256frobust::{
    detached_sign as sphincsshake256frobust_detached_sign,
    keypair as sphincsshake256frobust_keypair, open as sphincsshake256frobust_open,
    public_key_bytes as sphincsshake256frobust_public_key_bytes,
    secret_key_bytes as sphincsshake256frobust_secret_key_bytes,
    sign as sphincsshake256frobust_sign, signature_bytes as sphincsshake256frobust_signature_bytes,
    verify_detached_signature as sphincsshake256frobust_verify_detached_signature,
};
pub use crate::sphincsshake256fsimple::{
    detached_sign as sphincsshake256fsimple_detached_sign,
    keypair as sphincsshake256fsimple_keypair, open as sphincsshake256fsimple_open,
    public_key_bytes as sphincsshake256fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake256fsimple_secret_key_bytes,
    sign as sphincsshake256fsimple_sign, signature_bytes as sphincsshake256fsimple_signature_bytes,
    verify_detached_signature as sphincsshake256fsimple_verify_detached_signature,
};
pub use crate::sphincsshake256srobust::{
    detached_sign as sphincsshake256srobust_detached_sign,
    keypair as sphincsshake256srobust_keypair, open as sphincsshake256srobust_open,
    public_key_bytes as sphincsshake256srobust_public_key_bytes,
    secret_key_bytes as sphincsshake256srobust_secret_key_bytes,
    sign as sphincsshake256srobust_sign, signature_bytes as sphincsshake256srobust_signature_bytes,
    verify_detached_signature as sphincsshake256srobust_verify_detached_signature,
};
pub use crate::sphincsshake256ssimple::{
    detached_sign as sphincsshake256ssimple_detached_sign,
    keypair as sphincsshake256ssimple_keypair, open as sphincsshake256ssimple_open,
    public_key_bytes as sphincsshake256ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake256ssimple_secret_key_bytes,
    sign as sphincsshake256ssimple_sign, signature_bytes as sphincsshake256ssimple_signature_bytes,
    verify_detached_signature as sphincsshake256ssimple_verify_detached_signature,
};
