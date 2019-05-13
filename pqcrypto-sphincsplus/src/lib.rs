//! # sphincsplus
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * sphincs-haraka-128s-simple - clean
//! * sphincs-haraka-128s-robust - clean
//! * sphincs-haraka-128f-simple - clean
//! * sphincs-haraka-128f-robust - clean
//! * sphincs-haraka-192s-simple - clean
//! * sphincs-haraka-192s-robust - clean
//! * sphincs-haraka-192f-simple - clean
//! * sphincs-haraka-192f-robust - clean
//! * sphincs-haraka-256s-simple - clean
//! * sphincs-haraka-256s-robust - clean
//! * sphincs-haraka-256f-simple - clean
//! * sphincs-haraka-256f-robust - clean
//! * sphincs-shake256-128s-simple - clean
//! * sphincs-shake256-128s-robust - clean
//! * sphincs-shake256-128f-simple - clean
//! * sphincs-shake256-128f-robust - clean
//! * sphincs-shake256-192s-simple - clean
//! * sphincs-shake256-192s-robust - clean
//! * sphincs-shake256-192f-simple - clean
//! * sphincs-shake256-192f-robust - clean
//! * sphincs-shake256-256s-simple - clean
//! * sphincs-shake256-256s-robust - clean
//! * sphincs-shake256-256f-simple - clean
//! * sphincs-shake256-256f-robust - clean
//! * sphincs-sha256-128s-simple - clean
//! * sphincs-sha256-128s-robust - clean
//! * sphincs-sha256-128f-simple - clean
//! * sphincs-sha256-128f-robust - clean
//! * sphincs-sha256-192s-simple - clean
//! * sphincs-sha256-192s-robust - clean
//! * sphincs-sha256-192f-simple - clean
//! * sphincs-sha256-192f-robust - clean
//! * sphincs-sha256-256s-simple - clean
//! * sphincs-sha256-256s-robust - clean
//! * sphincs-sha256-256f-simple - clean
//! * sphincs-sha256-256f-robust - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

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
pub mod sphincssha256128frobust;
pub mod sphincssha256128fsimple;
pub mod sphincssha256128srobust;
pub mod sphincssha256128ssimple;
pub mod sphincssha256192frobust;
pub mod sphincssha256192fsimple;
pub mod sphincssha256192srobust;
pub mod sphincssha256192ssimple;
pub mod sphincssha256256frobust;
pub mod sphincssha256256fsimple;
pub mod sphincssha256256srobust;
pub mod sphincssha256256ssimple;
pub mod sphincsshake256128frobust;
pub mod sphincsshake256128fsimple;
pub mod sphincsshake256128srobust;
pub mod sphincsshake256128ssimple;
pub mod sphincsshake256192frobust;
pub mod sphincsshake256192fsimple;
pub mod sphincsshake256192srobust;
pub mod sphincsshake256192ssimple;
pub mod sphincsshake256256frobust;
pub mod sphincsshake256256fsimple;
pub mod sphincsshake256256srobust;
pub mod sphincsshake256256ssimple;

pub use crate::sphincsharaka128frobust::{
    keypair as sphincsharaka128frobust_keypair,
    public_key_bytes as sphincsharaka128frobust_public_key_bytes,
    secret_key_bytes as sphincsharaka128frobust_secret_key_bytes,
    signature_bytes as sphincsharaka128frobust_signature_bytes,
};
pub use crate::sphincsharaka128fsimple::{
    keypair as sphincsharaka128fsimple_keypair,
    public_key_bytes as sphincsharaka128fsimple_public_key_bytes,
    secret_key_bytes as sphincsharaka128fsimple_secret_key_bytes,
    signature_bytes as sphincsharaka128fsimple_signature_bytes,
};
pub use crate::sphincsharaka128srobust::{
    keypair as sphincsharaka128srobust_keypair,
    public_key_bytes as sphincsharaka128srobust_public_key_bytes,
    secret_key_bytes as sphincsharaka128srobust_secret_key_bytes,
    signature_bytes as sphincsharaka128srobust_signature_bytes,
};
pub use crate::sphincsharaka128ssimple::{
    keypair as sphincsharaka128ssimple_keypair,
    public_key_bytes as sphincsharaka128ssimple_public_key_bytes,
    secret_key_bytes as sphincsharaka128ssimple_secret_key_bytes,
    signature_bytes as sphincsharaka128ssimple_signature_bytes,
};
pub use crate::sphincsharaka192frobust::{
    keypair as sphincsharaka192frobust_keypair,
    public_key_bytes as sphincsharaka192frobust_public_key_bytes,
    secret_key_bytes as sphincsharaka192frobust_secret_key_bytes,
    signature_bytes as sphincsharaka192frobust_signature_bytes,
};
pub use crate::sphincsharaka192fsimple::{
    keypair as sphincsharaka192fsimple_keypair,
    public_key_bytes as sphincsharaka192fsimple_public_key_bytes,
    secret_key_bytes as sphincsharaka192fsimple_secret_key_bytes,
    signature_bytes as sphincsharaka192fsimple_signature_bytes,
};
pub use crate::sphincsharaka192srobust::{
    keypair as sphincsharaka192srobust_keypair,
    public_key_bytes as sphincsharaka192srobust_public_key_bytes,
    secret_key_bytes as sphincsharaka192srobust_secret_key_bytes,
    signature_bytes as sphincsharaka192srobust_signature_bytes,
};
pub use crate::sphincsharaka192ssimple::{
    keypair as sphincsharaka192ssimple_keypair,
    public_key_bytes as sphincsharaka192ssimple_public_key_bytes,
    secret_key_bytes as sphincsharaka192ssimple_secret_key_bytes,
    signature_bytes as sphincsharaka192ssimple_signature_bytes,
};
pub use crate::sphincsharaka256frobust::{
    keypair as sphincsharaka256frobust_keypair,
    public_key_bytes as sphincsharaka256frobust_public_key_bytes,
    secret_key_bytes as sphincsharaka256frobust_secret_key_bytes,
    signature_bytes as sphincsharaka256frobust_signature_bytes,
};
pub use crate::sphincsharaka256fsimple::{
    keypair as sphincsharaka256fsimple_keypair,
    public_key_bytes as sphincsharaka256fsimple_public_key_bytes,
    secret_key_bytes as sphincsharaka256fsimple_secret_key_bytes,
    signature_bytes as sphincsharaka256fsimple_signature_bytes,
};
pub use crate::sphincsharaka256srobust::{
    keypair as sphincsharaka256srobust_keypair,
    public_key_bytes as sphincsharaka256srobust_public_key_bytes,
    secret_key_bytes as sphincsharaka256srobust_secret_key_bytes,
    signature_bytes as sphincsharaka256srobust_signature_bytes,
};
pub use crate::sphincsharaka256ssimple::{
    keypair as sphincsharaka256ssimple_keypair,
    public_key_bytes as sphincsharaka256ssimple_public_key_bytes,
    secret_key_bytes as sphincsharaka256ssimple_secret_key_bytes,
    signature_bytes as sphincsharaka256ssimple_signature_bytes,
};
pub use crate::sphincssha256128frobust::{
    keypair as sphincssha256128frobust_keypair,
    public_key_bytes as sphincssha256128frobust_public_key_bytes,
    secret_key_bytes as sphincssha256128frobust_secret_key_bytes,
    signature_bytes as sphincssha256128frobust_signature_bytes,
};
pub use crate::sphincssha256128fsimple::{
    keypair as sphincssha256128fsimple_keypair,
    public_key_bytes as sphincssha256128fsimple_public_key_bytes,
    secret_key_bytes as sphincssha256128fsimple_secret_key_bytes,
    signature_bytes as sphincssha256128fsimple_signature_bytes,
};
pub use crate::sphincssha256128srobust::{
    keypair as sphincssha256128srobust_keypair,
    public_key_bytes as sphincssha256128srobust_public_key_bytes,
    secret_key_bytes as sphincssha256128srobust_secret_key_bytes,
    signature_bytes as sphincssha256128srobust_signature_bytes,
};
pub use crate::sphincssha256128ssimple::{
    keypair as sphincssha256128ssimple_keypair,
    public_key_bytes as sphincssha256128ssimple_public_key_bytes,
    secret_key_bytes as sphincssha256128ssimple_secret_key_bytes,
    signature_bytes as sphincssha256128ssimple_signature_bytes,
};
pub use crate::sphincssha256192frobust::{
    keypair as sphincssha256192frobust_keypair,
    public_key_bytes as sphincssha256192frobust_public_key_bytes,
    secret_key_bytes as sphincssha256192frobust_secret_key_bytes,
    signature_bytes as sphincssha256192frobust_signature_bytes,
};
pub use crate::sphincssha256192fsimple::{
    keypair as sphincssha256192fsimple_keypair,
    public_key_bytes as sphincssha256192fsimple_public_key_bytes,
    secret_key_bytes as sphincssha256192fsimple_secret_key_bytes,
    signature_bytes as sphincssha256192fsimple_signature_bytes,
};
pub use crate::sphincssha256192srobust::{
    keypair as sphincssha256192srobust_keypair,
    public_key_bytes as sphincssha256192srobust_public_key_bytes,
    secret_key_bytes as sphincssha256192srobust_secret_key_bytes,
    signature_bytes as sphincssha256192srobust_signature_bytes,
};
pub use crate::sphincssha256192ssimple::{
    keypair as sphincssha256192ssimple_keypair,
    public_key_bytes as sphincssha256192ssimple_public_key_bytes,
    secret_key_bytes as sphincssha256192ssimple_secret_key_bytes,
    signature_bytes as sphincssha256192ssimple_signature_bytes,
};
pub use crate::sphincssha256256frobust::{
    keypair as sphincssha256256frobust_keypair,
    public_key_bytes as sphincssha256256frobust_public_key_bytes,
    secret_key_bytes as sphincssha256256frobust_secret_key_bytes,
    signature_bytes as sphincssha256256frobust_signature_bytes,
};
pub use crate::sphincssha256256fsimple::{
    keypair as sphincssha256256fsimple_keypair,
    public_key_bytes as sphincssha256256fsimple_public_key_bytes,
    secret_key_bytes as sphincssha256256fsimple_secret_key_bytes,
    signature_bytes as sphincssha256256fsimple_signature_bytes,
};
pub use crate::sphincssha256256srobust::{
    keypair as sphincssha256256srobust_keypair,
    public_key_bytes as sphincssha256256srobust_public_key_bytes,
    secret_key_bytes as sphincssha256256srobust_secret_key_bytes,
    signature_bytes as sphincssha256256srobust_signature_bytes,
};
pub use crate::sphincssha256256ssimple::{
    keypair as sphincssha256256ssimple_keypair,
    public_key_bytes as sphincssha256256ssimple_public_key_bytes,
    secret_key_bytes as sphincssha256256ssimple_secret_key_bytes,
    signature_bytes as sphincssha256256ssimple_signature_bytes,
};
pub use crate::sphincsshake256128frobust::{
    keypair as sphincsshake256128frobust_keypair,
    public_key_bytes as sphincsshake256128frobust_public_key_bytes,
    secret_key_bytes as sphincsshake256128frobust_secret_key_bytes,
    signature_bytes as sphincsshake256128frobust_signature_bytes,
};
pub use crate::sphincsshake256128fsimple::{
    keypair as sphincsshake256128fsimple_keypair,
    public_key_bytes as sphincsshake256128fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake256128fsimple_secret_key_bytes,
    signature_bytes as sphincsshake256128fsimple_signature_bytes,
};
pub use crate::sphincsshake256128srobust::{
    keypair as sphincsshake256128srobust_keypair,
    public_key_bytes as sphincsshake256128srobust_public_key_bytes,
    secret_key_bytes as sphincsshake256128srobust_secret_key_bytes,
    signature_bytes as sphincsshake256128srobust_signature_bytes,
};
pub use crate::sphincsshake256128ssimple::{
    keypair as sphincsshake256128ssimple_keypair,
    public_key_bytes as sphincsshake256128ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake256128ssimple_secret_key_bytes,
    signature_bytes as sphincsshake256128ssimple_signature_bytes,
};
pub use crate::sphincsshake256192frobust::{
    keypair as sphincsshake256192frobust_keypair,
    public_key_bytes as sphincsshake256192frobust_public_key_bytes,
    secret_key_bytes as sphincsshake256192frobust_secret_key_bytes,
    signature_bytes as sphincsshake256192frobust_signature_bytes,
};
pub use crate::sphincsshake256192fsimple::{
    keypair as sphincsshake256192fsimple_keypair,
    public_key_bytes as sphincsshake256192fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake256192fsimple_secret_key_bytes,
    signature_bytes as sphincsshake256192fsimple_signature_bytes,
};
pub use crate::sphincsshake256192srobust::{
    keypair as sphincsshake256192srobust_keypair,
    public_key_bytes as sphincsshake256192srobust_public_key_bytes,
    secret_key_bytes as sphincsshake256192srobust_secret_key_bytes,
    signature_bytes as sphincsshake256192srobust_signature_bytes,
};
pub use crate::sphincsshake256192ssimple::{
    keypair as sphincsshake256192ssimple_keypair,
    public_key_bytes as sphincsshake256192ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake256192ssimple_secret_key_bytes,
    signature_bytes as sphincsshake256192ssimple_signature_bytes,
};
pub use crate::sphincsshake256256frobust::{
    keypair as sphincsshake256256frobust_keypair,
    public_key_bytes as sphincsshake256256frobust_public_key_bytes,
    secret_key_bytes as sphincsshake256256frobust_secret_key_bytes,
    signature_bytes as sphincsshake256256frobust_signature_bytes,
};
pub use crate::sphincsshake256256fsimple::{
    keypair as sphincsshake256256fsimple_keypair,
    public_key_bytes as sphincsshake256256fsimple_public_key_bytes,
    secret_key_bytes as sphincsshake256256fsimple_secret_key_bytes,
    signature_bytes as sphincsshake256256fsimple_signature_bytes,
};
pub use crate::sphincsshake256256srobust::{
    keypair as sphincsshake256256srobust_keypair,
    public_key_bytes as sphincsshake256256srobust_public_key_bytes,
    secret_key_bytes as sphincsshake256256srobust_secret_key_bytes,
    signature_bytes as sphincsshake256256srobust_signature_bytes,
};
pub use crate::sphincsshake256256ssimple::{
    keypair as sphincsshake256256ssimple_keypair,
    public_key_bytes as sphincsshake256256ssimple_public_key_bytes,
    secret_key_bytes as sphincsshake256256ssimple_secret_key_bytes,
    signature_bytes as sphincsshake256256ssimple_signature_bytes,
};
