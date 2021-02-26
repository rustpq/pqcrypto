//! # rainbow
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * rainbowI-circumzenithal - clean
//! * rainbowI-classic - clean
//! * rainbowI-compressed - clean
//! * rainbowIII-circumzenithal - clean
//! * rainbowIII-classic - clean
//! * rainbowIII-compressed - clean
//! * rainbowV-circumzenithal - clean
//! * rainbowV-classic - clean
//! * rainbowV-compressed - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!
//! # Notes
//! This implementation requires a lot of stack space. You need to specify
//! ``RUST_MIN_STACK=800000000``, probably.

#![allow(clippy::len_without_is_empty)]

pub mod ffi;
pub mod rainbowicircumzenithal;
pub mod rainbowiclassic;
pub mod rainbowicompressed;
pub mod rainbowiiicircumzenithal;
pub mod rainbowiiiclassic;
pub mod rainbowiiicompressed;
pub mod rainbowvcircumzenithal;
pub mod rainbowvclassic;
pub mod rainbowvcompressed;

pub use crate::rainbowicircumzenithal::{
    detached_sign as rainbowicircumzenithal_detached_sign,
    keypair as rainbowicircumzenithal_keypair, open as rainbowicircumzenithal_open,
    public_key_bytes as rainbowicircumzenithal_public_key_bytes,
    secret_key_bytes as rainbowicircumzenithal_secret_key_bytes,
    sign as rainbowicircumzenithal_sign, signature_bytes as rainbowicircumzenithal_signature_bytes,
    verify_detached_signature as rainbowicircumzenithal_verify_detached_signature,
};
pub use crate::rainbowiclassic::{
    detached_sign as rainbowiclassic_detached_sign, keypair as rainbowiclassic_keypair,
    open as rainbowiclassic_open, public_key_bytes as rainbowiclassic_public_key_bytes,
    secret_key_bytes as rainbowiclassic_secret_key_bytes, sign as rainbowiclassic_sign,
    signature_bytes as rainbowiclassic_signature_bytes,
    verify_detached_signature as rainbowiclassic_verify_detached_signature,
};
pub use crate::rainbowicompressed::{
    detached_sign as rainbowicompressed_detached_sign, keypair as rainbowicompressed_keypair,
    open as rainbowicompressed_open, public_key_bytes as rainbowicompressed_public_key_bytes,
    secret_key_bytes as rainbowicompressed_secret_key_bytes, sign as rainbowicompressed_sign,
    signature_bytes as rainbowicompressed_signature_bytes,
    verify_detached_signature as rainbowicompressed_verify_detached_signature,
};
pub use crate::rainbowiiicircumzenithal::{
    detached_sign as rainbowiiicircumzenithal_detached_sign,
    keypair as rainbowiiicircumzenithal_keypair, open as rainbowiiicircumzenithal_open,
    public_key_bytes as rainbowiiicircumzenithal_public_key_bytes,
    secret_key_bytes as rainbowiiicircumzenithal_secret_key_bytes,
    sign as rainbowiiicircumzenithal_sign,
    signature_bytes as rainbowiiicircumzenithal_signature_bytes,
    verify_detached_signature as rainbowiiicircumzenithal_verify_detached_signature,
};
pub use crate::rainbowiiiclassic::{
    detached_sign as rainbowiiiclassic_detached_sign, keypair as rainbowiiiclassic_keypair,
    open as rainbowiiiclassic_open, public_key_bytes as rainbowiiiclassic_public_key_bytes,
    secret_key_bytes as rainbowiiiclassic_secret_key_bytes, sign as rainbowiiiclassic_sign,
    signature_bytes as rainbowiiiclassic_signature_bytes,
    verify_detached_signature as rainbowiiiclassic_verify_detached_signature,
};
pub use crate::rainbowiiicompressed::{
    detached_sign as rainbowiiicompressed_detached_sign, keypair as rainbowiiicompressed_keypair,
    open as rainbowiiicompressed_open, public_key_bytes as rainbowiiicompressed_public_key_bytes,
    secret_key_bytes as rainbowiiicompressed_secret_key_bytes, sign as rainbowiiicompressed_sign,
    signature_bytes as rainbowiiicompressed_signature_bytes,
    verify_detached_signature as rainbowiiicompressed_verify_detached_signature,
};
pub use crate::rainbowvcircumzenithal::{
    detached_sign as rainbowvcircumzenithal_detached_sign,
    keypair as rainbowvcircumzenithal_keypair, open as rainbowvcircumzenithal_open,
    public_key_bytes as rainbowvcircumzenithal_public_key_bytes,
    secret_key_bytes as rainbowvcircumzenithal_secret_key_bytes,
    sign as rainbowvcircumzenithal_sign, signature_bytes as rainbowvcircumzenithal_signature_bytes,
    verify_detached_signature as rainbowvcircumzenithal_verify_detached_signature,
};
pub use crate::rainbowvclassic::{
    detached_sign as rainbowvclassic_detached_sign, keypair as rainbowvclassic_keypair,
    open as rainbowvclassic_open, public_key_bytes as rainbowvclassic_public_key_bytes,
    secret_key_bytes as rainbowvclassic_secret_key_bytes, sign as rainbowvclassic_sign,
    signature_bytes as rainbowvclassic_signature_bytes,
    verify_detached_signature as rainbowvclassic_verify_detached_signature,
};
pub use crate::rainbowvcompressed::{
    detached_sign as rainbowvcompressed_detached_sign, keypair as rainbowvcompressed_keypair,
    open as rainbowvcompressed_open, public_key_bytes as rainbowvcompressed_public_key_bytes,
    secret_key_bytes as rainbowvcompressed_secret_key_bytes, sign as rainbowvcompressed_sign,
    signature_bytes as rainbowvcompressed_signature_bytes,
    verify_detached_signature as rainbowvcompressed_verify_detached_signature,
};
