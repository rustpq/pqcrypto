//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * hqc-128-1-cca2
//!  * hqc-192-1-cca2
//!  * hqc-192-2-cca2
//!  * hqc-256-1-cca2
//!  * hqc-256-2-cca2
//!  * hqc-256-3-cca2
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

pub const PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 3165;
pub const PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 3125;
pub const PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 6234;
pub const PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 5539;
pub const PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 5499;
pub const PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 10981;
pub const PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 5924;
pub const PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 5884;
pub const PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 11749;
pub const PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 8029;
pub const PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 7989;
pub const PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 15961;
pub const PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 8543;
pub const PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 8503;
pub const PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 16985;
pub const PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 8937;
pub const PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 8897;
pub const PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 17777;
pub const PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_BYTES: usize = 64;

#[link(name = "hqc-128-1-cca2_leaktime")]
extern "C" {
    pub fn PQCLEAN_HQC1281CCA2_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQC1281CCA2_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQC1281CCA2_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "hqc-192-1-cca2_leaktime")]
extern "C" {
    pub fn PQCLEAN_HQC1921CCA2_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQC1921CCA2_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQC1921CCA2_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "hqc-192-2-cca2_leaktime")]
extern "C" {
    pub fn PQCLEAN_HQC1922CCA2_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQC1922CCA2_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQC1922CCA2_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "hqc-256-1-cca2_leaktime")]
extern "C" {
    pub fn PQCLEAN_HQC2561CCA2_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQC2561CCA2_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQC2561CCA2_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "hqc-256-2-cca2_leaktime")]
extern "C" {
    pub fn PQCLEAN_HQC2562CCA2_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQC2562CCA2_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQC2562CCA2_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "hqc-256-3-cca2_leaktime")]
extern "C" {
    pub fn PQCLEAN_HQC2563CCA2_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_HQC2563CCA2_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_HQC2563CCA2_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_hqc1281cca2_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQC1281CCA2_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQC1281CCA2_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQC1281CCA2_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQC1281CCA2_LEAKTIME_crypto_kem_dec(
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
mod test_hqc1921cca2_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQC1921CCA2_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQC1921CCA2_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQC1921CCA2_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQC1921CCA2_LEAKTIME_crypto_kem_dec(
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
mod test_hqc1922cca2_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQC1922CCA2_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQC1922CCA2_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQC1922CCA2_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQC1922CCA2_LEAKTIME_crypto_kem_dec(
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
mod test_hqc2561cca2_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQC2561CCA2_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQC2561CCA2_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQC2561CCA2_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQC2561CCA2_LEAKTIME_crypto_kem_dec(
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
mod test_hqc2562cca2_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQC2562CCA2_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQC2562CCA2_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQC2562CCA2_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQC2562CCA2_LEAKTIME_crypto_kem_dec(
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
mod test_hqc2563cca2_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_HQC2563CCA2_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_HQC2563CCA2_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_HQC2563CCA2_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_HQC2563CCA2_LEAKTIME_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
