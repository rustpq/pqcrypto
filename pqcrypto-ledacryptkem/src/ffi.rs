//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * ledakemlt12
//!  * ledakemlt32
//!  * ledakemlt52
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 50;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 6520;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 6544;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_BYTES: usize = 32;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 66;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 12032;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 12064;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_BYTES: usize = 48;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 82;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 19040;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 19080;
#[deprecated(note = "Insecure cryptography, do not use in production")]
pub const PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_BYTES: usize = 64;

#[link(name = "ledakemlt12_leaktime")]
extern "C" {
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "ledakemlt32_leaktime")]
extern "C" {
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[link(name = "ledakemlt52_leaktime")]
extern "C" {
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT52_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT52_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    #[deprecated(note = "Insecure cryptography, do not use in production")]
    pub fn PQCLEAN_LEDAKEMLT52_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_ledakemlt12_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_dec(
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
mod test_ledakemlt32_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_dec(
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
mod test_ledakemlt52_leaktime {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = vec![0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = vec![0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = vec![0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = vec![0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT52_LEAKTIME_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT52_LEAKTIME_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_LEDAKEMLT52_LEAKTIME_crypto_kem_dec(
                    ss2.as_mut_ptr(),
                    ct.as_ptr(),
                    sk.as_ptr()
                )
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
