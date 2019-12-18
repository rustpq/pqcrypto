//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * qtesla-p-I
//!  * qtesla-p-III
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

pub const PQCLEAN_QTESLAPI_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 5184;
pub const PQCLEAN_QTESLAPI_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 14880;
pub const PQCLEAN_QTESLAPI_CLEAN_CRYPTO_BYTES: usize = 2592;
pub const PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 12352;
pub const PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 38432;
pub const PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_BYTES: usize = 5664;

#[link(name = "qtesla-p-I_clean")]
extern "C" {
    pub fn PQCLEAN_QTESLAPI_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_QTESLAPI_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_QTESLAPI_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_QTESLAPI_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_QTESLAPI_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "qtesla-p-III_clean")]
extern "C" {
    pub fn PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_QTESLAPIII_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_qteslapi_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_QTESLAPI_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_QTESLAPI_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_QTESLAPI_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_QTESLAPI_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_QTESLAPI_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_QTESLAPI_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m = Vec::with_capacity(mlen + PQCLEAN_QTESLAPI_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_QTESLAPI_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_QTESLAPI_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ) < 0
            );
        }
    }
}
#[cfg(test)]
mod test_qteslapiii_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = [0u8; PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = [0u8; PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = [0u8; PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = [0u8; PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m = Vec::with_capacity(mlen + PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr()
                )
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_QTESLAPIII_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_QTESLAPIII_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ) < 0
            );
        }
    }
}
