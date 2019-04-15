//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * frodokem640shake
//!  * frodokem976aes
//!  * frodokem976shake
//!  * frodokem1344aes
//!  * frodokem1344shake
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

pub const PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 19888;
pub const PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 9616;
pub const PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 9720;
pub const PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_BYTES: usize = 16;
pub const PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 31296;
pub const PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 15632;
pub const PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 15744;
pub const PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_BYTES: usize = 24;
pub const PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 31296;
pub const PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 15632;
pub const PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 15744;
pub const PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_BYTES: usize = 24;
pub const PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 43088;
pub const PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 21520;
pub const PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 21632;
pub const PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 43088;
pub const PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 21520;
pub const PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 21632;
pub const PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_BYTES: usize = 32;

#[link(name = "frodo")]
extern "C" {
    pub fn PQCLEAN_FRODOKEM640SHAKE_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM640SHAKE_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM640SHAKE_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FRODOKEM976AES_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM976AES_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM976AES_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FRODOKEM976SHAKE_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM976SHAKE_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM976SHAKE_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FRODOKEM1344AES_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM1344AES_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM1344AES_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FRODOKEM1344SHAKE_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM1344SHAKE_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_FRODOKEM1344SHAKE_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_frodokem640shake_clean {
    use super::*;
    use std::mem;
    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk: [u8; PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_PUBLICKEYBYTES] = mem::uninitialized();
            let mut sk: [u8; PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_SECRETKEYBYTES] = mem::uninitialized();
            let mut ct: [u8; PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_CIPHERTEXTBYTES] = mem::uninitialized();
            let mut ss1: [u8; PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_BYTES] = mem::uninitialized();
            let mut ss2: [u8; PQCLEAN_FRODOKEM640SHAKE_CLEAN_CRYPTO_BYTES] = mem::uninitialized();

            assert_eq!(
                0,
                PQCLEAN_FRODOKEM640SHAKE_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM640SHAKE_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM640SHAKE_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(ss1, ss2);
        }
    }
}
#[cfg(test)]
mod test_frodokem976aes_clean {
    use super::*;
    use std::mem;
    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk: [u8; PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_PUBLICKEYBYTES] = mem::uninitialized();
            let mut sk: [u8; PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_SECRETKEYBYTES] = mem::uninitialized();
            let mut ct: [u8; PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_CIPHERTEXTBYTES] = mem::uninitialized();
            let mut ss1: [u8; PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_BYTES] = mem::uninitialized();
            let mut ss2: [u8; PQCLEAN_FRODOKEM976AES_CLEAN_CRYPTO_BYTES] = mem::uninitialized();

            assert_eq!(
                0,
                PQCLEAN_FRODOKEM976AES_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM976AES_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM976AES_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(ss1, ss2);
        }
    }
}
#[cfg(test)]
mod test_frodokem976shake_clean {
    use super::*;
    use std::mem;
    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk: [u8; PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_PUBLICKEYBYTES] = mem::uninitialized();
            let mut sk: [u8; PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_SECRETKEYBYTES] = mem::uninitialized();
            let mut ct: [u8; PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_CIPHERTEXTBYTES] = mem::uninitialized();
            let mut ss1: [u8; PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_BYTES] = mem::uninitialized();
            let mut ss2: [u8; PQCLEAN_FRODOKEM976SHAKE_CLEAN_CRYPTO_BYTES] = mem::uninitialized();

            assert_eq!(
                0,
                PQCLEAN_FRODOKEM976SHAKE_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM976SHAKE_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM976SHAKE_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(ss1, ss2);
        }
    }
}
#[cfg(test)]
mod test_frodokem1344aes_clean {
    use super::*;
    use std::mem;
    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk: [u8; PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_PUBLICKEYBYTES] = mem::uninitialized();
            let mut sk: [u8; PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_SECRETKEYBYTES] = mem::uninitialized();
            let mut ct: [u8; PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_CIPHERTEXTBYTES] = mem::uninitialized();
            let mut ss1: [u8; PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_BYTES] = mem::uninitialized();
            let mut ss2: [u8; PQCLEAN_FRODOKEM1344AES_CLEAN_CRYPTO_BYTES] = mem::uninitialized();

            assert_eq!(
                0,
                PQCLEAN_FRODOKEM1344AES_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM1344AES_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM1344AES_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(ss1, ss2);
        }
    }
}
#[cfg(test)]
mod test_frodokem1344shake_clean {
    use super::*;
    use std::mem;
    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk: [u8; PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_PUBLICKEYBYTES] = mem::uninitialized();
            let mut sk: [u8; PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_SECRETKEYBYTES] = mem::uninitialized();
            let mut ct: [u8; PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_CIPHERTEXTBYTES] = mem::uninitialized();
            let mut ss1: [u8; PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_BYTES] = mem::uninitialized();
            let mut ss2: [u8; PQCLEAN_FRODOKEM1344SHAKE_CLEAN_CRYPTO_BYTES] = mem::uninitialized();

            assert_eq!(
                0,
                PQCLEAN_FRODOKEM1344SHAKE_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM1344SHAKE_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FRODOKEM1344SHAKE_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(ss1, ss2);
        }
    }
}
