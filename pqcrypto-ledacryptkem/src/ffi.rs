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

pub const PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 50;
pub const PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 6520;
pub const PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 6544;
pub const PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 66;
pub const PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 12032;
pub const PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 12064;
pub const PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_BYTES: usize = 48;
pub const PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_SECRETKEYBYTES: usize = 82;
pub const PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_PUBLICKEYBYTES: usize = 19040;
pub const PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_CIPHERTEXTBYTES: usize = 19080;
pub const PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_BYTES: usize = 64;

#[link(name = "ledacryptkem")]
extern "C" {
    pub fn PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;

    pub fn PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_LEDAKEMLT32_LEAKTIME_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;

    pub fn PQCLEAN_LEDAKEMLT52_LEAKTIME_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_LEDAKEMLT52_LEAKTIME_crypto_kem_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> c_int;
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
            let mut pk = [0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = [0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = [0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = [0u8; PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_BYTES];

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
            let mut pk = [0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = [0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = [0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = [0u8; PQCLEAN_LEDAKEMLT32_LEAKTIME_CRYPTO_BYTES];

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
            let mut pk = [0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_SECRETKEYBYTES];
            let mut ct = [0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = [0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_BYTES];
            let mut ss2 = [0u8; PQCLEAN_LEDAKEMLT52_LEAKTIME_CRYPTO_BYTES];

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
