//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * falcon-512
//!  * falcon-padded-512
//!  * falcon-1024
//!  * falcon-padded-1024
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

// ensures we link correctly
#[allow(unused_imports)]
use pqcrypto_internals::*;

pub const PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1281;
pub const PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 897;
pub const PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES: usize = 752;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCON512_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1281;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCON512_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 897;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCON512_AVX2_CRYPTO_BYTES: usize = 752;

#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCON512_AARCH64_CRYPTO_SECRETKEYBYTES: usize = 1281;
#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCON512_AARCH64_CRYPTO_PUBLICKEYBYTES: usize = 897;
#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCON512_AARCH64_CRYPTO_BYTES: usize = 752;

pub const PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1281;
pub const PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 897;
pub const PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES: usize = 666;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_SECRETKEYBYTES: usize = 1281;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 897;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_BYTES: usize = 666;

#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES: usize = 1281;
#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_PUBLICKEYBYTES: usize = 897;
#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES: usize = 666;

pub const PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2305;
pub const PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1793;
pub const PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES: usize = 1462;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCON1024_AVX2_CRYPTO_SECRETKEYBYTES: usize = 2305;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCON1024_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1793;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCON1024_AVX2_CRYPTO_BYTES: usize = 1462;

#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCON1024_AARCH64_CRYPTO_SECRETKEYBYTES: usize = 2305;
#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCON1024_AARCH64_CRYPTO_PUBLICKEYBYTES: usize = 1793;
#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCON1024_AARCH64_CRYPTO_BYTES: usize = 1462;

pub const PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2305;
pub const PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1793;
pub const PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES: usize = 1280;

#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_SECRETKEYBYTES: usize = 2305;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_PUBLICKEYBYTES: usize = 1793;
#[cfg(enable_x86_avx2)]
pub const PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_BYTES: usize = 1280;

#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_SECRETKEYBYTES: usize = 2305;
#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_PUBLICKEYBYTES: usize = 1793;
#[cfg(enable_aarch64_neon)]
pub const PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_BYTES: usize = 1280;

#[link(name = "falcon-512_clean")]
extern "C" {
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "falcon-512_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON512_AVX2_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON512_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON512_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON512_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON512_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_aarch64_neon)]
#[link(name = "falcon-512_aarch64")]
extern "C" {
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON512_AARCH64_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON512_AARCH64_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON512_AARCH64_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON512_AARCH64_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON512_AARCH64_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "falcon-padded-512_clean")]
extern "C" {
    pub fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "falcon-padded-512_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED512_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_aarch64_neon)]
#[link(name = "falcon-padded-512_aarch64")]
extern "C" {
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "falcon-1024_clean")]
extern "C" {
    pub fn PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FALCON1024_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "falcon-1024_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON1024_AVX2_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON1024_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON1024_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON1024_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCON1024_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_aarch64_neon)]
#[link(name = "falcon-1024_aarch64")]
extern "C" {
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON1024_AARCH64_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON1024_AARCH64_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON1024_AARCH64_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON1024_AARCH64_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCON1024_AARCH64_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[link(name = "falcon-padded-1024_clean")]
extern "C" {
    pub fn PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_x86_avx2)]
#[link(name = "falcon-padded-1024_avx2")]
extern "C" {
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_x86_avx2)]
    pub fn PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(enable_aarch64_neon)]
#[link(name = "falcon-padded-1024_aarch64")]
extern "C" {
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    #[cfg(enable_aarch64_neon)]
    pub fn PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

}

#[cfg(test)]
mod test_falcon512_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m = Vec::with_capacity(mlen + PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_falcon512_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCON512_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCON512_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCON512_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCON512_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCON512_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCON512_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCON512_AVX2_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m = Vec::with_capacity(mlen + PQCLEAN_FALCON512_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCON512_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_aarch64_neon, feature = "neon"))]
mod test_falcon512_aarch64 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCON512_AARCH64_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCON512_AARCH64_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCON512_AARCH64_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCON512_AARCH64_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCON512_AARCH64_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCON512_AARCH64_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCON512_AARCH64_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AARCH64_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m = Vec::with_capacity(mlen + PQCLEAN_FALCON512_AARCH64_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AARCH64_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AARCH64_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_AARCH64_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AARCH64_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCON512_AARCH64_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON512_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON512_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_falconpadded512_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_falconpadded512_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_aarch64_neon, feature = "neon"))]
mod test_falconpadded512_aarch64 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_falcon1024_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m = Vec::with_capacity(mlen + PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_falcon1024_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCON1024_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCON1024_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCON1024_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCON1024_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCON1024_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCON1024_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AVX2_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m = Vec::with_capacity(mlen + PQCLEAN_FALCON1024_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCON1024_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_aarch64_neon, feature = "neon"))]
mod test_falcon1024_aarch64 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCON1024_AARCH64_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCON1024_AARCH64_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCON1024_AARCH64_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCON1024_AARCH64_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCON1024_AARCH64_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCON1024_AARCH64_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m = Vec::with_capacity(mlen + PQCLEAN_FALCON1024_AARCH64_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCON1024_AARCH64_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCON1024_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(test)]
mod test_falconpadded1024_clean {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_x86_avx2, feature = "avx2"))]
mod test_falconpadded1024_avx2 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;
    use std::is_x86_feature_detected;

    #[test]
    fn test_ffi() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCONPADDED1024_AVX2_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_AVX2_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}

#[cfg(all(test, enable_aarch64_neon, feature = "neon"))]
mod test_falconpadded1024_aarch64 {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_BYTES);
            let mut smlen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign"
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk.as_ptr(),
                ),
                "sign_open"
            );
            unpacked_m.set_len(mlen);
            assert_eq!(unpacked_m, msg);

            // check verification fails with wrong pk
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                ),
                "keypair"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ),
                "sign_open"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                ),
                "sign_signature"
            );
            assert!(
                smlen <= PQCLEAN_FALCONPADDED1024_AARCH64_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                ),
                "sign_verify"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ),
                "sign_verify alt pk"
            );
            assert_eq!(
                -1,
                PQCLEAN_FALCONPADDED1024_AARCH64_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                ),
                "sign_verify wrong length"
            );
        }
    }
}
