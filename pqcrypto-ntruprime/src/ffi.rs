//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * ntrulpr653
//!  * ntrulpr761
//!  * ntrulpr857
//!  * ntrulpr953
//!  * ntrulpr1013
//!  * ntrulpr1277
//!  * sntrup653
//!  * sntrup761
//!  * sntrup857
//!  * sntrup953
//!  * sntrup1013
//!  * sntrup1277
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

// ensures we link correctly
#[allow(unused_imports)]
use pqcrypto_internals::*;

pub const PQCLEAN_NTRULPR653_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1125;
pub const PQCLEAN_NTRULPR653_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 897;
pub const PQCLEAN_NTRULPR653_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1025;
pub const PQCLEAN_NTRULPR653_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR653_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1125;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR653_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 897;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR653_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1025;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR653_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_NTRULPR761_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1294;
pub const PQCLEAN_NTRULPR761_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1039;
pub const PQCLEAN_NTRULPR761_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1167;
pub const PQCLEAN_NTRULPR761_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR761_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1294;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR761_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1039;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR761_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1167;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR761_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_NTRULPR857_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1463;
pub const PQCLEAN_NTRULPR857_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1184;
pub const PQCLEAN_NTRULPR857_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1312;
pub const PQCLEAN_NTRULPR857_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR857_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1463;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR857_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1184;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR857_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1312;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR857_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_NTRULPR953_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1652;
pub const PQCLEAN_NTRULPR953_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1349;
pub const PQCLEAN_NTRULPR953_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1477;
pub const PQCLEAN_NTRULPR953_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR953_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1652;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR953_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1349;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR953_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1477;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR953_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1773;
pub const PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1455;
pub const PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1583;
pub const PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR1013_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1773;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR1013_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1455;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR1013_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1583;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR1013_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2231;
pub const PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1847;
pub const PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1975;
pub const PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR1277_AVX2_CRYPTO_SECRETKEYBYTES: usize = 2231;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR1277_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1847;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR1277_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1975;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_NTRULPR1277_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_SNTRUP653_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1518;
pub const PQCLEAN_SNTRUP653_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 994;
pub const PQCLEAN_SNTRUP653_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 897;
pub const PQCLEAN_SNTRUP653_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP653_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1518;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP653_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 994;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP653_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 897;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP653_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_SNTRUP761_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1763;
pub const PQCLEAN_SNTRUP761_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1158;
pub const PQCLEAN_SNTRUP761_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1039;
pub const PQCLEAN_SNTRUP761_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP761_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1763;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP761_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1158;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP761_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1039;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP761_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_SNTRUP857_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1999;
pub const PQCLEAN_SNTRUP857_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1322;
pub const PQCLEAN_SNTRUP857_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1184;
pub const PQCLEAN_SNTRUP857_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP857_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1999;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP857_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1322;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP857_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1184;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP857_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_SNTRUP953_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2254;
pub const PQCLEAN_SNTRUP953_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1505;
pub const PQCLEAN_SNTRUP953_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1349;
pub const PQCLEAN_SNTRUP953_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP953_AVX2_CRYPTO_SECRETKEYBYTES: usize = 2254;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP953_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1505;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP953_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1349;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP953_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2417;
pub const PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1623;
pub const PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1455;
pub const PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP1013_AVX2_CRYPTO_SECRETKEYBYTES: usize = 2417;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP1013_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1623;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP1013_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1455;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP1013_AVX2_CRYPTO_BYTES: usize = 32;

pub const PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 3059;
pub const PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 2067;
pub const PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1847;
pub const PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_BYTES: usize = 32;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP1277_AVX2_CRYPTO_SECRETKEYBYTES: usize = 3059;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP1277_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 2067;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP1277_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1847;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_SNTRUP1277_AVX2_CRYPTO_BYTES: usize = 32;

#[link(name = "ntrulpr653_clean")]
extern "C" {
    pub fn PQCLEAN_NTRULPR653_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRULPR653_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRULPR653_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "ntrulpr653_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR653_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR653_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR653_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "ntrulpr761_clean")]
extern "C" {
    pub fn PQCLEAN_NTRULPR761_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRULPR761_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRULPR761_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "ntrulpr761_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR761_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR761_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR761_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "ntrulpr857_clean")]
extern "C" {
    pub fn PQCLEAN_NTRULPR857_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRULPR857_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRULPR857_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "ntrulpr857_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR857_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR857_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR857_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "ntrulpr953_clean")]
extern "C" {
    pub fn PQCLEAN_NTRULPR953_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRULPR953_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRULPR953_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "ntrulpr953_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR953_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR953_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR953_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "ntrulpr1013_clean")]
extern "C" {
    pub fn PQCLEAN_NTRULPR1013_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRULPR1013_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRULPR1013_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "ntrulpr1013_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR1013_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR1013_AVX2_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR1013_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "ntrulpr1277_clean")]
extern "C" {
    pub fn PQCLEAN_NTRULPR1277_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRULPR1277_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRULPR1277_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "ntrulpr1277_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR1277_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR1277_AVX2_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_NTRULPR1277_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "sntrup653_clean")]
extern "C" {
    pub fn PQCLEAN_SNTRUP653_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_SNTRUP653_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    pub fn PQCLEAN_SNTRUP653_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "sntrup653_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP653_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP653_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP653_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "sntrup761_clean")]
extern "C" {
    pub fn PQCLEAN_SNTRUP761_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_SNTRUP761_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    pub fn PQCLEAN_SNTRUP761_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "sntrup761_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP761_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP761_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP761_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "sntrup857_clean")]
extern "C" {
    pub fn PQCLEAN_SNTRUP857_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_SNTRUP857_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    pub fn PQCLEAN_SNTRUP857_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "sntrup857_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP857_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP857_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP857_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "sntrup953_clean")]
extern "C" {
    pub fn PQCLEAN_SNTRUP953_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_SNTRUP953_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    pub fn PQCLEAN_SNTRUP953_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "sntrup953_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP953_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP953_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP953_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "sntrup1013_clean")]
extern "C" {
    pub fn PQCLEAN_SNTRUP1013_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_SNTRUP1013_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SNTRUP1013_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "sntrup1013_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP1013_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP1013_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP1013_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "sntrup1277_clean")]
extern "C" {
    pub fn PQCLEAN_SNTRUP1277_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_SNTRUP1277_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_SNTRUP1277_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_x86_avx2)]
#[link(name = "sntrup1277_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP1277_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP1277_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_SNTRUP1277_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_ntrulpr653_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR653_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR653_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR653_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR653_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR653_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR653_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR653_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR653_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_ntrulpr653_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR653_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR653_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR653_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR653_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR653_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR653_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR653_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR653_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_ntrulpr761_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR761_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR761_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR761_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR761_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR761_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR761_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR761_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR761_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_ntrulpr761_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR761_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR761_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR761_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR761_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR761_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR761_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR761_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR761_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_ntrulpr857_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR857_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR857_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR857_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR857_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR857_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR857_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR857_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR857_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_ntrulpr857_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR857_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR857_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR857_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR857_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR857_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR857_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR857_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR857_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_ntrulpr953_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR953_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR953_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR953_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR953_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR953_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR953_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR953_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR953_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_ntrulpr953_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR953_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR953_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR953_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR953_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR953_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR953_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR953_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR953_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_ntrulpr1013_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR1013_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR1013_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR1013_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR1013_CLEAN_crypto_kem_dec(
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
mod test_ntrulpr1013_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR1013_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR1013_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR1013_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR1013_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR1013_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR1013_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR1013_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR1013_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_ntrulpr1277_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR1277_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR1277_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR1277_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR1277_CLEAN_crypto_kem_dec(
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
mod test_ntrulpr1277_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRULPR1277_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRULPR1277_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRULPR1277_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRULPR1277_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRULPR1277_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRULPR1277_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR1277_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRULPR1277_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_sntrup653_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP653_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP653_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP653_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP653_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP653_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP653_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP653_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP653_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sntrup653_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP653_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP653_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP653_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP653_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP653_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP653_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP653_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP653_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_sntrup761_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP761_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP761_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP761_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP761_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP761_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP761_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP761_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP761_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sntrup761_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP761_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP761_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP761_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP761_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP761_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP761_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP761_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP761_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_sntrup857_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP857_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP857_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP857_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP857_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP857_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP857_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP857_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP857_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sntrup857_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP857_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP857_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP857_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP857_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP857_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP857_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP857_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP857_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_sntrup953_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP953_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP953_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP953_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP953_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP953_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP953_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP953_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP953_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sntrup953_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP953_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP953_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP953_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP953_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP953_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP953_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP953_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP953_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_sntrup1013_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP1013_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP1013_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP1013_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP1013_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sntrup1013_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP1013_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP1013_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP1013_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP1013_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP1013_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP1013_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP1013_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP1013_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(test)]
mod test_sntrup1277_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP1277_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP1277_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP1277_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP1277_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_sntrup1277_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SNTRUP1277_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SNTRUP1277_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SNTRUP1277_AVX2_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SNTRUP1277_AVX2_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SNTRUP1277_AVX2_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SNTRUP1277_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP1277_AVX2_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_SNTRUP1277_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
