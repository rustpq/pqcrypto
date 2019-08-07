//! # rainbow
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * rainbowIIIc-classic - clean
//! * rainbowIIIc-cyclic - clean
//! * rainbowIIIc-cyclic-compressed - clean
//! * rainbowIa-classic - clean
//! * rainbowIa-cyclic - clean
//! * rainbowIa-cyclic-compressed - clean
//! * rainbowVc-classic - clean
//! * rainbowVc-cyclic - clean
//! * rainbowVc-cyclic-compressed - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!
//! # Notes
//! The underlying ``clean`` implementions currently contain undefined
//! behaviour, so they may crash!

#![allow(clippy::len_without_is_empty)]

pub mod ffi;

pub mod rainbowiaclassic;
pub mod rainbowiacyclic;
pub mod rainbowiacycliccompressed;
pub mod rainbowiiicclassic;
pub mod rainbowiiiccyclic;
pub mod rainbowiiiccycliccompressed;
pub mod rainbowvcclassic;
pub mod rainbowvccyclic;
pub mod rainbowvccycliccompressed;

pub use crate::rainbowiaclassic::{
    detached_sign as rainbowiaclassic_detached_sign, keypair as rainbowiaclassic_keypair,
    open as rainbowiaclassic_open, public_key_bytes as rainbowiaclassic_public_key_bytes,
    secret_key_bytes as rainbowiaclassic_secret_key_bytes, sign as rainbowiaclassic_sign,
    signature_bytes as rainbowiaclassic_signature_bytes,
    verify_detached_signature as rainbowiaclassic_verify_detached_signature,
};
pub use crate::rainbowiacyclic::{
    detached_sign as rainbowiacyclic_detached_sign, keypair as rainbowiacyclic_keypair,
    open as rainbowiacyclic_open, public_key_bytes as rainbowiacyclic_public_key_bytes,
    secret_key_bytes as rainbowiacyclic_secret_key_bytes, sign as rainbowiacyclic_sign,
    signature_bytes as rainbowiacyclic_signature_bytes,
    verify_detached_signature as rainbowiacyclic_verify_detached_signature,
};
pub use crate::rainbowiacycliccompressed::{
    detached_sign as rainbowiacycliccompressed_detached_sign,
    keypair as rainbowiacycliccompressed_keypair, open as rainbowiacycliccompressed_open,
    public_key_bytes as rainbowiacycliccompressed_public_key_bytes,
    secret_key_bytes as rainbowiacycliccompressed_secret_key_bytes,
    sign as rainbowiacycliccompressed_sign,
    signature_bytes as rainbowiacycliccompressed_signature_bytes,
    verify_detached_signature as rainbowiacycliccompressed_verify_detached_signature,
};
pub use crate::rainbowiiicclassic::{
    detached_sign as rainbowiiicclassic_detached_sign, keypair as rainbowiiicclassic_keypair,
    open as rainbowiiicclassic_open, public_key_bytes as rainbowiiicclassic_public_key_bytes,
    secret_key_bytes as rainbowiiicclassic_secret_key_bytes, sign as rainbowiiicclassic_sign,
    signature_bytes as rainbowiiicclassic_signature_bytes,
    verify_detached_signature as rainbowiiicclassic_verify_detached_signature,
};
pub use crate::rainbowiiiccyclic::{
    detached_sign as rainbowiiiccyclic_detached_sign, keypair as rainbowiiiccyclic_keypair,
    open as rainbowiiiccyclic_open, public_key_bytes as rainbowiiiccyclic_public_key_bytes,
    secret_key_bytes as rainbowiiiccyclic_secret_key_bytes, sign as rainbowiiiccyclic_sign,
    signature_bytes as rainbowiiiccyclic_signature_bytes,
    verify_detached_signature as rainbowiiiccyclic_verify_detached_signature,
};
pub use crate::rainbowiiiccycliccompressed::{
    detached_sign as rainbowiiiccycliccompressed_detached_sign,
    keypair as rainbowiiiccycliccompressed_keypair, open as rainbowiiiccycliccompressed_open,
    public_key_bytes as rainbowiiiccycliccompressed_public_key_bytes,
    secret_key_bytes as rainbowiiiccycliccompressed_secret_key_bytes,
    sign as rainbowiiiccycliccompressed_sign,
    signature_bytes as rainbowiiiccycliccompressed_signature_bytes,
    verify_detached_signature as rainbowiiiccycliccompressed_verify_detached_signature,
};
pub use crate::rainbowvcclassic::{
    detached_sign as rainbowvcclassic_detached_sign, keypair as rainbowvcclassic_keypair,
    open as rainbowvcclassic_open, public_key_bytes as rainbowvcclassic_public_key_bytes,
    secret_key_bytes as rainbowvcclassic_secret_key_bytes, sign as rainbowvcclassic_sign,
    signature_bytes as rainbowvcclassic_signature_bytes,
    verify_detached_signature as rainbowvcclassic_verify_detached_signature,
};
pub use crate::rainbowvccyclic::{
    detached_sign as rainbowvccyclic_detached_sign, keypair as rainbowvccyclic_keypair,
    open as rainbowvccyclic_open, public_key_bytes as rainbowvccyclic_public_key_bytes,
    secret_key_bytes as rainbowvccyclic_secret_key_bytes, sign as rainbowvccyclic_sign,
    signature_bytes as rainbowvccyclic_signature_bytes,
    verify_detached_signature as rainbowvccyclic_verify_detached_signature,
};
pub use crate::rainbowvccycliccompressed::{
    detached_sign as rainbowvccycliccompressed_detached_sign,
    keypair as rainbowvccycliccompressed_keypair, open as rainbowvccycliccompressed_open,
    public_key_bytes as rainbowvccycliccompressed_public_key_bytes,
    secret_key_bytes as rainbowvccycliccompressed_secret_key_bytes,
    sign as rainbowvccycliccompressed_sign,
    signature_bytes as rainbowvccycliccompressed_signature_bytes,
    verify_detached_signature as rainbowvccycliccompressed_verify_detached_signature,
};
