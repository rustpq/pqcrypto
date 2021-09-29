//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * firesaber
//!  * lightsaber
//!  * saber
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

// ensures we link correctly
#[allow(unused_imports)]
use pqcrypto_internals::*;

pub const PQCLEAN_FIRESABER_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 3040;
pub const PQCLEAN_FIRESABER_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1312;
pub const PQCLEAN_FIRESABER_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1472;
pub const PQCLEAN_FIRESABER_CLEAN_CRYPTO_BYTES: usize = 32;
#[cfg(enable_avx2)]
pub const PQCLEAN_FIRESABER_AVX2_CRYPTO_SECRETKEYBYTES: usize = 3040;
#[cfg(enable_avx2)]
pub const PQCLEAN_FIRESABER_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1312;
#[cfg(enable_avx2)]
pub const PQCLEAN_FIRESABER_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1472;
#[cfg(enable_avx2)]
pub const PQCLEAN_FIRESABER_AVX2_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1568;
pub const PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 672;
pub const PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 736;
pub const PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_BYTES: usize = 32;
#[cfg(enable_avx2)]
pub const PQCLEAN_LIGHTSABER_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1568;
#[cfg(enable_avx2)]
pub const PQCLEAN_LIGHTSABER_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 672;
#[cfg(enable_avx2)]
pub const PQCLEAN_LIGHTSABER_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 736;
#[cfg(enable_avx2)]
pub const PQCLEAN_LIGHTSABER_AVX2_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_SABER_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2304;
pub const PQCLEAN_SABER_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 992;
pub const PQCLEAN_SABER_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1088;
pub const PQCLEAN_SABER_CLEAN_CRYPTO_BYTES: usize = 32;
#[cfg(enable_avx2)]
pub const PQCLEAN_SABER_AVX2_CRYPTO_SECRETKEYBYTES: usize = 2304;
#[cfg(enable_avx2)]
pub const PQCLEAN_SABER_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 992;
#[cfg(enable_avx2)]
pub const PQCLEAN_SABER_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1088;
#[cfg(enable_avx2)]
pub const PQCLEAN_SABER_AVX2_CRYPTO_BYTES: usize = 32;

#[link(name = "firesaber_clean")]
extern "C" {
    pub fn PQCLEAN_FIRESABER_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FIRESABER_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;
    pub fn PQCLEAN_FIRESABER_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_avx2)]
#[link(name = "firesaber_avx2")]
extern "C" {
    #[cfg(enable_avx2)]
    pub fn PQCLEAN_FIRESABER_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_FIRESABER_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_FIRESABER_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}
#[link(name = "lightsaber_clean")]
extern "C" {
    pub fn PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_avx2)]
#[link(name = "lightsaber_avx2")]
extern "C" {
    #[cfg(enable_avx2)]
    pub fn PQCLEAN_LIGHTSABER_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_LIGHTSABER_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8)
        -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_LIGHTSABER_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}
#[link(name = "saber_clean")]
extern "C" {
    pub fn PQCLEAN_SABER_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_SABER_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_SABER_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
}

#[cfg(enable_avx2)]
#[link(name = "saber_avx2")]
extern "C" {
    #[cfg(enable_avx2)]
    pub fn PQCLEAN_SABER_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_SABER_AVX2_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_SABER_AVX2_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
}

#[cfg(test)]
mod test_firesaber_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_FIRESABER_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FIRESABER_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_FIRESABER_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_FIRESABER_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_FIRESABER_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_FIRESABER_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FIRESABER_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FIRESABER_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
#[cfg(all(test, enable_avx2, feature = "avx2"))]
mod test_firesaber_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            run_test_ffi();
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn run_test_ffi() {
        let mut pk = vec![0u8; PQCLEAN_FIRESABER_AVX2_CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; PQCLEAN_FIRESABER_AVX2_CRYPTO_SECRETKEYBYTES];
        let mut ct = vec![0u8; PQCLEAN_FIRESABER_AVX2_CRYPTO_CIPHERTEXTBYTES];
        let mut ss1 = vec![0u8; PQCLEAN_FIRESABER_AVX2_CRYPTO_BYTES];
        let mut ss2 = vec![0u8; PQCLEAN_FIRESABER_AVX2_CRYPTO_BYTES];

        assert_eq!(
            0,
            PQCLEAN_FIRESABER_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_FIRESABER_AVX2_crypto_kem_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_FIRESABER_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
        );
        assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
    }
}
#[cfg(test)]
mod test_lightsaber_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_LIGHTSABER_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
#[cfg(all(test, enable_avx2, feature = "avx2"))]
mod test_lightsaber_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            run_test_ffi();
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn run_test_ffi() {
        let mut pk = vec![0u8; PQCLEAN_LIGHTSABER_AVX2_CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; PQCLEAN_LIGHTSABER_AVX2_CRYPTO_SECRETKEYBYTES];
        let mut ct = vec![0u8; PQCLEAN_LIGHTSABER_AVX2_CRYPTO_CIPHERTEXTBYTES];
        let mut ss1 = vec![0u8; PQCLEAN_LIGHTSABER_AVX2_CRYPTO_BYTES];
        let mut ss2 = vec![0u8; PQCLEAN_LIGHTSABER_AVX2_CRYPTO_BYTES];

        assert_eq!(
            0,
            PQCLEAN_LIGHTSABER_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_LIGHTSABER_AVX2_crypto_kem_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_LIGHTSABER_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
        );
        assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
    }
}
#[cfg(test)]
mod test_saber_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_SABER_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_SABER_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_SABER_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_SABER_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_SABER_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_SABER_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SABER_CLEAN_crypto_kem_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_SABER_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
#[cfg(all(test, enable_avx2, feature = "avx2"))]
mod test_saber_avx2 {
    use super::*;
    use alloc::vec;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            run_test_ffi();
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn run_test_ffi() {
        let mut pk = vec![0u8; PQCLEAN_SABER_AVX2_CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; PQCLEAN_SABER_AVX2_CRYPTO_SECRETKEYBYTES];
        let mut ct = vec![0u8; PQCLEAN_SABER_AVX2_CRYPTO_CIPHERTEXTBYTES];
        let mut ss1 = vec![0u8; PQCLEAN_SABER_AVX2_CRYPTO_BYTES];
        let mut ss2 = vec![0u8; PQCLEAN_SABER_AVX2_CRYPTO_BYTES];

        assert_eq!(
            0,
            PQCLEAN_SABER_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_SABER_AVX2_crypto_kem_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_SABER_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
        );
        assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
    }
}
