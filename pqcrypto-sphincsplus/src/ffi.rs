//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * sphincs-shake-128f-simple
//!  * sphincs-shake-128s-simple
//!  * sphincs-shake-192f-simple
//!  * sphincs-shake-192s-simple
//!  * sphincs-shake-256f-simple
//!  * sphincs-shake-256s-simple
//!  * sphincs-sha2-128f-simple
//!  * sphincs-sha2-128s-simple
//!  * sphincs-sha2-192f-simple
//!  * sphincs-sha2-192s-simple
//!  * sphincs-sha2-256f-simple
//!  * sphincs-sha2-256s-simple
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

// ensures we link correctly
#[allow(unused_imports)]
use pqcrypto_internals::*;

pub const PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 17088;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 64;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 32;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_BYTES: usize = 17088;

pub const PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 7856;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 64;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 32;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_BYTES: usize = 7856;

pub const PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 35664;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 96;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 48;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_BYTES: usize = 35664;

pub const PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 16224;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 96;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 48;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_BYTES: usize = 16224;

pub const PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 49856;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 128;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 64;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_BYTES: usize = 49856;

pub const PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 29792;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 128;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 64;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_BYTES: usize = 29792;

pub const PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 17088;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 64;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 32;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_BYTES: usize = 17088;

pub const PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 32;
pub const PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 7856;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 64;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 32;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_BYTES: usize = 7856;

pub const PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 35664;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 96;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 48;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_BYTES: usize = 35664;

pub const PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 96;
pub const PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 48;
pub const PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 16224;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 96;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 48;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_BYTES: usize = 16224;

pub const PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES: usize = 49856;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 128;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 64;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_BYTES: usize = 49856;

pub const PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 128;
pub const PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 64;
pub const PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES: usize = 29792;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES: usize = 128;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 64;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_BYTES: usize = 29792;

#[link(name = "sphincs-shake-128f-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-shake-128f-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-shake-128s-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-shake-128s-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-shake-192f-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-shake-192f-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-shake-192s-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-shake-192s-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-shake-256f-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-shake-256f-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-shake-256s-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-shake-256s-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-sha2-128f-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-sha2-128f-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-sha2-128s-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-sha2-128s-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-sha2-192f-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-sha2-192f-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-sha2-192s-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-sha2-192s-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-sha2-256f-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-sha2-256f-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "sphincs-sha2-256s-simple_clean")]
extern "C" {
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "sphincs-sha2-256s-simple_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(test)]
mod test_sphincsshake128fsimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincsshake128fsimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincsshake128ssimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincsshake128ssimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE128SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincsshake192fsimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincsshake192fsimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincsshake192ssimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincsshake192ssimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE192SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincsshake256fsimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincsshake256fsimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincsshake256ssimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincsshake256ssimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHAKE256SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincssha2128fsimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincssha2128fsimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincssha2128ssimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincssha2128ssimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2128SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincssha2192fsimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincssha2192fsimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincssha2192ssimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincssha2192ssimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2192SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincssha2256fsimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincssha2256fsimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_sphincssha2256ssimple_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sphincssha2256ssimple_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::rng();
            let mut mlen: usize = rng.random::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.random()).collect();

            let mut pk = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_SPHINCSSHA2256SSIMPLE_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}
