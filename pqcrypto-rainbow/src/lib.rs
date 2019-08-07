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

pub mod rainbowaclassic;
pub mod rainbowacyclic;
pub mod rainbowacycliccompressed;
pub mod rainbowcclassic;
pub mod rainbowcclassic;
pub mod rainbowccyclic;
pub mod rainbowccyclic;
pub mod rainbowccycliccompressed;
pub mod rainbowccycliccompressed;

pub use crate::rainbowaclassic::{
    detached_sign as rainbowaclassic_detached_sign, keypair as rainbowaclassic_keypair,
    open as rainbowaclassic_open, public_key_bytes as rainbowaclassic_public_key_bytes,
    secret_key_bytes as rainbowaclassic_secret_key_bytes, sign as rainbowaclassic_sign,
    signature_bytes as rainbowaclassic_signature_bytes,
    verify_detached_signature as rainbowaclassic_verify_detached_signature,
};
pub use crate::rainbowacyclic::{
    detached_sign as rainbowacyclic_detached_sign, keypair as rainbowacyclic_keypair,
    open as rainbowacyclic_open, public_key_bytes as rainbowacyclic_public_key_bytes,
    secret_key_bytes as rainbowacyclic_secret_key_bytes, sign as rainbowacyclic_sign,
    signature_bytes as rainbowacyclic_signature_bytes,
    verify_detached_signature as rainbowacyclic_verify_detached_signature,
};
pub use crate::rainbowacycliccompressed::{
    detached_sign as rainbowacycliccompressed_detached_sign,
    keypair as rainbowacycliccompressed_keypair, open as rainbowacycliccompressed_open,
    public_key_bytes as rainbowacycliccompressed_public_key_bytes,
    secret_key_bytes as rainbowacycliccompressed_secret_key_bytes,
    sign as rainbowacycliccompressed_sign,
    signature_bytes as rainbowacycliccompressed_signature_bytes,
    verify_detached_signature as rainbowacycliccompressed_verify_detached_signature,
};
pub use crate::rainbowcclassic::{
    detached_sign as rainbowcclassic_detached_sign, keypair as rainbowcclassic_keypair,
    open as rainbowcclassic_open, public_key_bytes as rainbowcclassic_public_key_bytes,
    secret_key_bytes as rainbowcclassic_secret_key_bytes, sign as rainbowcclassic_sign,
    signature_bytes as rainbowcclassic_signature_bytes,
    verify_detached_signature as rainbowcclassic_verify_detached_signature,
};
pub use crate::rainbowcclassic::{
    detached_sign as rainbowcclassic_detached_sign, keypair as rainbowcclassic_keypair,
    open as rainbowcclassic_open, public_key_bytes as rainbowcclassic_public_key_bytes,
    secret_key_bytes as rainbowcclassic_secret_key_bytes, sign as rainbowcclassic_sign,
    signature_bytes as rainbowcclassic_signature_bytes,
    verify_detached_signature as rainbowcclassic_verify_detached_signature,
};
pub use crate::rainbowccyclic::{
    detached_sign as rainbowccyclic_detached_sign, keypair as rainbowccyclic_keypair,
    open as rainbowccyclic_open, public_key_bytes as rainbowccyclic_public_key_bytes,
    secret_key_bytes as rainbowccyclic_secret_key_bytes, sign as rainbowccyclic_sign,
    signature_bytes as rainbowccyclic_signature_bytes,
    verify_detached_signature as rainbowccyclic_verify_detached_signature,
};
pub use crate::rainbowccyclic::{
    detached_sign as rainbowccyclic_detached_sign, keypair as rainbowccyclic_keypair,
    open as rainbowccyclic_open, public_key_bytes as rainbowccyclic_public_key_bytes,
    secret_key_bytes as rainbowccyclic_secret_key_bytes, sign as rainbowccyclic_sign,
    signature_bytes as rainbowccyclic_signature_bytes,
    verify_detached_signature as rainbowccyclic_verify_detached_signature,
};
pub use crate::rainbowccycliccompressed::{
    detached_sign as rainbowccycliccompressed_detached_sign,
    keypair as rainbowccycliccompressed_keypair, open as rainbowccycliccompressed_open,
    public_key_bytes as rainbowccycliccompressed_public_key_bytes,
    secret_key_bytes as rainbowccycliccompressed_secret_key_bytes,
    sign as rainbowccycliccompressed_sign,
    signature_bytes as rainbowccycliccompressed_signature_bytes,
    verify_detached_signature as rainbowccycliccompressed_verify_detached_signature,
};
pub use crate::rainbowccycliccompressed::{
    detached_sign as rainbowccycliccompressed_detached_sign,
    keypair as rainbowccycliccompressed_keypair, open as rainbowccycliccompressed_open,
    public_key_bytes as rainbowccycliccompressed_public_key_bytes,
    secret_key_bytes as rainbowccycliccompressed_secret_key_bytes,
    sign as rainbowccycliccompressed_sign,
    signature_bytes as rainbowccycliccompressed_signature_bytes,
    verify_detached_signature as rainbowccycliccompressed_verify_detached_signature,
};
