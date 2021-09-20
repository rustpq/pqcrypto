//! # ntruprime
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * ntrulpr653 - clean
//! * ntrulpr761 - clean
//! * ntrulpr857 - clean
//! * ntrulpr953 - clean
//! * ntrulpr1013 - clean
//! * ntrulpr1277 - clean
//! * sntrup653 - clean
//! * sntrup761 - clean
//! * sntrup857 - clean
//! * sntrup953 - clean
//! * sntrup1013 - clean
//! * sntrup1277 - clean
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
pub mod ntrulpr1013;
pub mod ntrulpr1277;
pub mod ntrulpr653;
pub mod ntrulpr761;
pub mod ntrulpr857;
pub mod ntrulpr953;
pub mod sntrup1013;
pub mod sntrup1277;
pub mod sntrup653;
pub mod sntrup761;
pub mod sntrup857;
pub mod sntrup953;

pub use crate::ntrulpr1013::{
    ciphertext_bytes as ntrulpr1013_ciphertext_bytes, decapsulate as ntrulpr1013_decapsulate,
    encapsulate as ntrulpr1013_encapsulate, keypair as ntrulpr1013_keypair,
    public_key_bytes as ntrulpr1013_public_key_bytes,
    secret_key_bytes as ntrulpr1013_secret_key_bytes,
    shared_secret_bytes as ntrulpr1013_shared_secret_bytes,
};
pub use crate::ntrulpr1277::{
    ciphertext_bytes as ntrulpr1277_ciphertext_bytes, decapsulate as ntrulpr1277_decapsulate,
    encapsulate as ntrulpr1277_encapsulate, keypair as ntrulpr1277_keypair,
    public_key_bytes as ntrulpr1277_public_key_bytes,
    secret_key_bytes as ntrulpr1277_secret_key_bytes,
    shared_secret_bytes as ntrulpr1277_shared_secret_bytes,
};
pub use crate::ntrulpr653::{
    ciphertext_bytes as ntrulpr653_ciphertext_bytes, decapsulate as ntrulpr653_decapsulate,
    encapsulate as ntrulpr653_encapsulate, keypair as ntrulpr653_keypair,
    public_key_bytes as ntrulpr653_public_key_bytes,
    secret_key_bytes as ntrulpr653_secret_key_bytes,
    shared_secret_bytes as ntrulpr653_shared_secret_bytes,
};
pub use crate::ntrulpr761::{
    ciphertext_bytes as ntrulpr761_ciphertext_bytes, decapsulate as ntrulpr761_decapsulate,
    encapsulate as ntrulpr761_encapsulate, keypair as ntrulpr761_keypair,
    public_key_bytes as ntrulpr761_public_key_bytes,
    secret_key_bytes as ntrulpr761_secret_key_bytes,
    shared_secret_bytes as ntrulpr761_shared_secret_bytes,
};
pub use crate::ntrulpr857::{
    ciphertext_bytes as ntrulpr857_ciphertext_bytes, decapsulate as ntrulpr857_decapsulate,
    encapsulate as ntrulpr857_encapsulate, keypair as ntrulpr857_keypair,
    public_key_bytes as ntrulpr857_public_key_bytes,
    secret_key_bytes as ntrulpr857_secret_key_bytes,
    shared_secret_bytes as ntrulpr857_shared_secret_bytes,
};
pub use crate::ntrulpr953::{
    ciphertext_bytes as ntrulpr953_ciphertext_bytes, decapsulate as ntrulpr953_decapsulate,
    encapsulate as ntrulpr953_encapsulate, keypair as ntrulpr953_keypair,
    public_key_bytes as ntrulpr953_public_key_bytes,
    secret_key_bytes as ntrulpr953_secret_key_bytes,
    shared_secret_bytes as ntrulpr953_shared_secret_bytes,
};
pub use crate::sntrup1013::{
    ciphertext_bytes as sntrup1013_ciphertext_bytes, decapsulate as sntrup1013_decapsulate,
    encapsulate as sntrup1013_encapsulate, keypair as sntrup1013_keypair,
    public_key_bytes as sntrup1013_public_key_bytes,
    secret_key_bytes as sntrup1013_secret_key_bytes,
    shared_secret_bytes as sntrup1013_shared_secret_bytes,
};
pub use crate::sntrup1277::{
    ciphertext_bytes as sntrup1277_ciphertext_bytes, decapsulate as sntrup1277_decapsulate,
    encapsulate as sntrup1277_encapsulate, keypair as sntrup1277_keypair,
    public_key_bytes as sntrup1277_public_key_bytes,
    secret_key_bytes as sntrup1277_secret_key_bytes,
    shared_secret_bytes as sntrup1277_shared_secret_bytes,
};
pub use crate::sntrup653::{
    ciphertext_bytes as sntrup653_ciphertext_bytes, decapsulate as sntrup653_decapsulate,
    encapsulate as sntrup653_encapsulate, keypair as sntrup653_keypair,
    public_key_bytes as sntrup653_public_key_bytes, secret_key_bytes as sntrup653_secret_key_bytes,
    shared_secret_bytes as sntrup653_shared_secret_bytes,
};
pub use crate::sntrup761::{
    ciphertext_bytes as sntrup761_ciphertext_bytes, decapsulate as sntrup761_decapsulate,
    encapsulate as sntrup761_encapsulate, keypair as sntrup761_keypair,
    public_key_bytes as sntrup761_public_key_bytes, secret_key_bytes as sntrup761_secret_key_bytes,
    shared_secret_bytes as sntrup761_shared_secret_bytes,
};
pub use crate::sntrup857::{
    ciphertext_bytes as sntrup857_ciphertext_bytes, decapsulate as sntrup857_decapsulate,
    encapsulate as sntrup857_encapsulate, keypair as sntrup857_keypair,
    public_key_bytes as sntrup857_public_key_bytes, secret_key_bytes as sntrup857_secret_key_bytes,
    shared_secret_bytes as sntrup857_shared_secret_bytes,
};
pub use crate::sntrup953::{
    ciphertext_bytes as sntrup953_ciphertext_bytes, decapsulate as sntrup953_decapsulate,
    encapsulate as sntrup953_encapsulate, keypair as sntrup953_keypair,
    public_key_bytes as sntrup953_public_key_bytes, secret_key_bytes as sntrup953_secret_key_bytes,
    shared_secret_bytes as sntrup953_shared_secret_bytes,
};
