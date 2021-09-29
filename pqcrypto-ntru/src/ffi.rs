//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * ntruhps2048509
//!  * ntruhps2048677
//!  * ntruhps4096821
//!  * ntruhrss701
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

// ensures we link correctly
#[allow(unused_imports)]
use pqcrypto_internals::*;

pub const PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 935;
pub const PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 699;
pub const PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 699;
pub const PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_BYTES: usize = 32;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_SECRETKEYBYTES: usize = 935;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 699;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 699;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1234;
pub const PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 930;
pub const PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 930;
pub const PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_BYTES: usize = 32;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1234;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 930;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 930;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1590;
pub const PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1230;
pub const PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1230;
pub const PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_BYTES: usize = 32;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1590;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1230;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1230;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1450;
pub const PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1138;
pub const PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1138;
pub const PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_BYTES: usize = 32;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1450;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1138;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_CIPHERTEXTBYTES: usize = 1138;
#[cfg(enable_avx2)]
pub const PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_BYTES: usize = 32;

#[link(name = "ntruhps2048509_clean")]
extern "C" {
    pub fn PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_avx2)]
#[link(name = "ntruhps2048509_avx2")]
extern "C" {
    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}
#[link(name = "ntruhps2048677_clean")]
extern "C" {
    pub fn PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_avx2)]
#[link(name = "ntruhps2048677_avx2")]
extern "C" {
    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}
#[link(name = "ntruhps4096821_clean")]
extern "C" {
    pub fn PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_avx2)]
#[link(name = "ntruhps4096821_avx2")]
extern "C" {
    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}
#[link(name = "ntruhrss701_clean")]
extern "C" {
    pub fn PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(enable_avx2)]
#[link(name = "ntruhrss701_avx2")]
extern "C" {
    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;

    #[cfg(enable_avx2)]
    pub fn PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_ntruhps2048509_clean {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRUHPS2048509_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_dec(
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
#[cfg(enable_avx2)]
mod test_ntruhps2048509_avx2 {
    use super::*;

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
        let mut pk = vec![0u8; PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_SECRETKEYBYTES];
        let mut ct = vec![0u8; PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_CIPHERTEXTBYTES];
        let mut ss1 = vec![0u8; PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_BYTES];
        let mut ss2 = vec![0u8; PQCLEAN_NTRUHPS2048509_AVX2_CRYPTO_BYTES];

        assert_eq!(
            0,
            PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_enc(
                ct.as_mut_ptr(),
                ss1.as_mut_ptr(),
                pk.as_ptr()
            )
        );
        assert_eq!(
            0,
            PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
        );
        assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
    }
}
#[cfg(test)]
mod test_ntruhps2048677_clean {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRUHPS2048677_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_dec(
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
#[cfg(enable_avx2)]
mod test_ntruhps2048677_avx2 {
    use super::*;

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
        let mut pk = vec![0u8; PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_SECRETKEYBYTES];
        let mut ct = vec![0u8; PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_CIPHERTEXTBYTES];
        let mut ss1 = vec![0u8; PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_BYTES];
        let mut ss2 = vec![0u8; PQCLEAN_NTRUHPS2048677_AVX2_CRYPTO_BYTES];

        assert_eq!(
            0,
            PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_enc(
                ct.as_mut_ptr(),
                ss1.as_mut_ptr(),
                pk.as_ptr()
            )
        );
        assert_eq!(
            0,
            PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
        );
        assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
    }
}
#[cfg(test)]
mod test_ntruhps4096821_clean {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec(
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
#[cfg(enable_avx2)]
mod test_ntruhps4096821_avx2 {
    use super::*;

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
        let mut pk = vec![0u8; PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_SECRETKEYBYTES];
        let mut ct = vec![0u8; PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_CIPHERTEXTBYTES];
        let mut ss1 = vec![0u8; PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_BYTES];
        let mut ss2 = vec![0u8; PQCLEAN_NTRUHPS4096821_AVX2_CRYPTO_BYTES];

        assert_eq!(
            0,
            PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_enc(
                ct.as_mut_ptr(),
                ss1.as_mut_ptr(),
                pk.as_ptr()
            )
        );
        assert_eq!(
            0,
            PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
        );
        assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
    }
}
#[cfg(test)]
mod test_ntruhrss701_clean {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_NTRUHRSS701_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_dec(
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
#[cfg(enable_avx2)]
mod test_ntruhrss701_avx2 {
    use super::*;

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
        let mut pk = vec![0u8; PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_PUBLICKEYBYTES];
        let mut sk = vec![0u8; PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_SECRETKEYBYTES];
        let mut ct = vec![0u8; PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_CIPHERTEXTBYTES];
        let mut ss1 = vec![0u8; PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_BYTES];
        let mut ss2 = vec![0u8; PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_BYTES];

        assert_eq!(
            0,
            PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr())
        );
        assert_eq!(
            0,
            PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
        );
        assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
    }
}
