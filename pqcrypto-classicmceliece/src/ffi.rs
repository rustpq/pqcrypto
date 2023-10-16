//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * mceliece348864
//!  * mceliece348864f
//!  * mceliece460896
//!  * mceliece460896f
//!  * mceliece6688128
//!  * mceliece6688128f
//!  * mceliece6960119
//!  * mceliece6960119f
//!  * mceliece8192128
//!  * mceliece8192128f
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

// ensures we link correctly
#[allow(unused_imports)]
use pqcrypto_internals::*;

pub const PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 6492;
pub const PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 261120;
pub const PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 96;
pub const PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE348864_AVX_CRYPTO_SECRETKEYBYTES: usize = 6492;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE348864_AVX_CRYPTO_PUBLICKEYBYTES: usize = 261120;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE348864_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 96;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE348864_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 6492;
pub const PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 261120;
pub const PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 96;
pub const PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE348864F_AVX_CRYPTO_SECRETKEYBYTES: usize = 6492;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE348864F_AVX_CRYPTO_PUBLICKEYBYTES: usize = 261120;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE348864F_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 96;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE348864F_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 13608;
pub const PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 524160;
pub const PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 156;
pub const PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE460896_AVX_CRYPTO_SECRETKEYBYTES: usize = 13608;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE460896_AVX_CRYPTO_PUBLICKEYBYTES: usize = 524160;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE460896_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 156;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE460896_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 13608;
pub const PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 524160;
pub const PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 156;
pub const PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE460896F_AVX_CRYPTO_SECRETKEYBYTES: usize = 13608;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE460896F_AVX_CRYPTO_PUBLICKEYBYTES: usize = 524160;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE460896F_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 156;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE460896F_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 13932;
pub const PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1044992;
pub const PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 208;
pub const PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6688128_AVX_CRYPTO_SECRETKEYBYTES: usize = 13932;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6688128_AVX_CRYPTO_PUBLICKEYBYTES: usize = 1044992;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6688128_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 208;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6688128_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 13932;
pub const PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1044992;
pub const PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 208;
pub const PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_SECRETKEYBYTES: usize = 13932;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_PUBLICKEYBYTES: usize = 1044992;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 208;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 13948;
pub const PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1047319;
pub const PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 194;
pub const PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6960119_AVX_CRYPTO_SECRETKEYBYTES: usize = 13948;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6960119_AVX_CRYPTO_PUBLICKEYBYTES: usize = 1047319;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6960119_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 194;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6960119_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 13948;
pub const PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1047319;
pub const PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 194;
pub const PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_SECRETKEYBYTES: usize = 13948;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_PUBLICKEYBYTES: usize = 1047319;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 194;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 14120;
pub const PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1357824;
pub const PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 208;
pub const PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE8192128_AVX_CRYPTO_SECRETKEYBYTES: usize = 14120;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE8192128_AVX_CRYPTO_PUBLICKEYBYTES: usize = 1357824;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE8192128_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 208;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE8192128_AVX_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 14120;
pub const PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1357824;
pub const PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 208;
pub const PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_SECRETKEYBYTES: usize = 14120;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_PUBLICKEYBYTES: usize = 1357824;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_CIPHERTEXTBYTES: usize = 208;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_BYTES: usize = 32;

#[link(name = "mceliece348864_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece348864_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE348864_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE348864_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE348864_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece348864f_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece348864f_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE348864F_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE348864F_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE348864F_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece460896_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece460896_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE460896_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE460896_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE460896_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece460896f_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece460896f_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE460896F_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE460896F_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE460896F_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece6688128_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece6688128_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6688128_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6688128_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6688128_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece6688128f_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece6688128f_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6688128F_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6688128F_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6688128F_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece6960119_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece6960119_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6960119_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6960119_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6960119_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece6960119f_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece6960119f_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6960119F_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6960119F_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE6960119F_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece8192128_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece8192128_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE8192128_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE8192128_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE8192128_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "mceliece8192128f_clean")]
extern "C" {
    pub fn PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "mceliece8192128f_avx")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_mceliece348864_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece348864_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE348864_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE348864_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE348864_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE348864_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE348864_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece348864f_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece348864f_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE348864F_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE348864F_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE348864F_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE348864F_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE348864F_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864F_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864F_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE348864F_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece460896_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece460896_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE460896_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE460896_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE460896_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE460896_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE460896_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece460896f_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece460896f_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE460896F_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE460896F_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE460896F_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE460896F_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE460896F_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896F_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896F_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE460896F_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece6688128_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece6688128_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE6688128_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE6688128_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE6688128_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE6688128_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE6688128_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece6688128f_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece6688128f_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE6688128F_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128F_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128F_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6688128F_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece6960119_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece6960119_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE6960119_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE6960119_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE6960119_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE6960119_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE6960119_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece6960119f_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece6960119f_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE6960119F_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119F_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119F_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE6960119F_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece8192128_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece8192128_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE8192128_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE8192128_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE8192128_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE8192128_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE8192128_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_mceliece8192128f_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_mceliece8192128f_avx {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_MCELIECE8192128F_AVX_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
