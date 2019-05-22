//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * sphincs-haraka-128s-simple
//!  * sphincs-haraka-128s-robust
//!  * sphincs-haraka-128f-simple
//!  * sphincs-haraka-128f-robust
//!  * sphincs-haraka-192s-simple
//!  * sphincs-haraka-192s-robust
//!  * sphincs-haraka-192f-simple
//!  * sphincs-haraka-192f-robust
//!  * sphincs-haraka-256s-simple
//!  * sphincs-haraka-256s-robust
//!  * sphincs-haraka-256f-simple
//!  * sphincs-haraka-256f-robust
//!  * sphincs-shake256-128s-simple
//!  * sphincs-shake256-128s-robust
//!  * sphincs-shake256-128f-simple
//!  * sphincs-shake256-128f-robust
//!  * sphincs-shake256-192s-simple
//!  * sphincs-shake256-192s-robust
//!  * sphincs-shake256-192f-simple
//!  * sphincs-shake256-192f-robust
//!  * sphincs-shake256-256s-simple
//!  * sphincs-shake256-256s-robust
//!  * sphincs-shake256-256f-simple
//!  * sphincs-shake256-256f-robust
//!  * sphincs-sha256-128s-simple
//!  * sphincs-sha256-128s-robust
//!  * sphincs-sha256-128f-simple
//!  * sphincs-sha256-128f-robust
//!  * sphincs-sha256-192s-simple
//!  * sphincs-sha256-192s-robust
//!  * sphincs-sha256-192f-simple
//!  * sphincs-sha256-192f-robust
//!  * sphincs-sha256-256s-simple
//!  * sphincs-sha256-256s-robust
//!  * sphincs-sha256-256f-simple
//!  * sphincs-sha256-256f-robust
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

pub const PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 8080;
pub const PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_BYTES: usize = 8080;
pub const PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 16976;
pub const PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_BYTES: usize = 16976;
pub const PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 17064;
pub const PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_BYTES: usize = 17064;
pub const PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 35664;
pub const PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_BYTES: usize = 35664;
pub const PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 29792;
pub const PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_BYTES: usize = 29792;
pub const PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 49216;
pub const PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_BYTES: usize = 49216;
pub const PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 8080;
pub const PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_BYTES: usize = 8080;
pub const PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 16976;
pub const PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_BYTES: usize = 16976;
pub const PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 17064;
pub const PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_BYTES: usize = 17064;
pub const PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 35664;
pub const PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_BYTES: usize = 35664;
pub const PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 29792;
pub const PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_BYTES: usize = 29792;
pub const PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 49216;
pub const PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_BYTES: usize = 49216;
pub const PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 8080;
pub const PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES: usize = 8080;
pub const PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 16976;
pub const PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_BYTES: usize = 16976;
pub const PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 17064;
pub const PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_BYTES: usize = 17064;
pub const PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 35664;
pub const PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_BYTES: usize = 35664;
pub const PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 29792;
pub const PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_BYTES: usize = 29792;
pub const PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 49216;
pub const PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_BYTES: usize = 49216;

#[link(name = "pqcrypto_internals")]
#[link(name = "sphincsplus")]
extern "C" {
    pub fn PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_sphincsharaka128ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka128srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka128fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka128frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka192ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka192srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka192fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka192frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka256ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka256srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka256fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsharaka256frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256128ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256128srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256128fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256128frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256192ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256192srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256192fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256192frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256256ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256256srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256256fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincsshake256256frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256128ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256128srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256128fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256128frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256128FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256192ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256192srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256192fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256192frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256192FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256256ssimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256256srobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256SROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256256fsimple_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
#[cfg(test)]
mod test_sphincssha256256frobust_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert_eq!(smlen, PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA256256FROBUST_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );
        }
    }
}
