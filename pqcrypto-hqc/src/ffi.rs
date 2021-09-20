//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * hqc-rmrs-128
//!  * hqc-rmrs-192
//!  * hqc-rmrs-256
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

// ensures we link correctly
#[allow(unused_imports)]
use pqcrypto_internals::*;

pub const PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2289;
pub const PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 2249;
pub const PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 4481;
pub const PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 4562;
pub const PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 4522;
pub const PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 9026;
pub const PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 7285;
pub const PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 7245;
pub const PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 14469;
pub const PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES: usize = 64;

#[link(name = "hqc-rmrs-128_clean")]
extern "C" {
    pub fn PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "hqc-rmrs-192_clean")]
extern "C" {
    pub fn PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "hqc-rmrs-256_clean")]
extern "C" {
    pub fn PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_hqcrmrs128_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
#[cfg(test)]
mod test_hqcrmrs192_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
#[cfg(test)]
mod test_hqcrmrs256_clean {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
