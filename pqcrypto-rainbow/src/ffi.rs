//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * rainbowIIIc-classic
//!  * rainbowIIIc-cyclic
//!  * rainbowIIIc-cyclic-compressed
//!  * rainbowIa-classic
//!  * rainbowIa-cyclic
//!  * rainbowIa-cyclic-compressed
//!  * rainbowVc-classic
//!  * rainbowVc-cyclic
//!  * rainbowVc-cyclic-compressed
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

pub const PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 511448;
pub const PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 710640;
pub const PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_BYTES: usize = 156;
pub const PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 511448;
pub const PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 206744;
pub const PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_BYTES: usize = 156;
pub const PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 206744;
pub const PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES: usize = 156;
pub const PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 92960;
pub const PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 148992;
pub const PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 92960;
pub const PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 58144;
pub const PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 58144;
pub const PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES: usize = 64;
pub const PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1227104;
pub const PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1705536;
pub const PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_BYTES: usize = 204;
pub const PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 1227104;
pub const PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 491936;
pub const PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_BYTES: usize = 204;
pub const PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 64;
pub const PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 491936;
pub const PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES: usize = 204;

#[link(name = "rainbowIIIc-classic_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "rainbowIIIc-cyclic_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "rainbowIIIc-cyclic-compressed_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "rainbowIa-classic_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "rainbowIa-cyclic_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "rainbowIa-cyclic-compressed_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "rainbowVc-classic_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "rainbowVc-cyclic_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[link(name = "rainbowVc-cyclic-compressed_clean")]
extern "C" {
    pub fn PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign(
        sm: *mut u8,
        smlen: *mut usize,
        msg: *const u8,
        len: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        pk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;
    pub fn PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod test_rainbowiiicclassic_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWIIICCLASSIC_CLEAN_crypto_sign_verify(
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
mod test_rainbowiiiccyclic_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWIIICCYCLIC_CLEAN_crypto_sign_verify(
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
mod test_rainbowiiiccycliccompressed_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt =
                vec![0u8; PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt =
                vec![0u8; PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig =
                vec![0u8; PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWIIICCYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
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
mod test_rainbowiaclassic_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWIACLASSIC_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWIACLASSIC_CLEAN_crypto_sign_verify(
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
mod test_rainbowiacyclic_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWIACYCLIC_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWIACYCLIC_CLEAN_crypto_sign_verify(
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
mod test_rainbowiacycliccompressed_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt =
                vec![0u8; PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt =
                vec![0u8; PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWIACYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
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
mod test_rainbowvcclassic_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWVCCLASSIC_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWVCCLASSIC_CLEAN_crypto_sign_verify(
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
mod test_rainbowvccyclic_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt = vec![0u8; PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt = vec![0u8; PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_BYTES];
            let mut sm = Vec::with_capacity(mlen + PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWVCCYCLIC_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWVCCYCLIC_CLEAN_crypto_sign_verify(
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
mod test_rainbowvccycliccompressed_clean {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();
            let mut mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();

            let mut pk = vec![0u8; PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = vec![0u8; PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut pk_alt =
                vec![0u8; PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk_alt =
                vec![0u8; PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut detached_sig = vec![0u8; PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES];
            let mut sm =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES);
            let mut smlen = 0;
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign(
                    sm.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    mlen,
                    sk.as_ptr()
                )
            );
            sm.set_len(smlen);

            let mut unpacked_m =
                Vec::with_capacity(mlen + PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES);
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_open(
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
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_keypair(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_open(
                    unpacked_m.as_mut_ptr(),
                    &mut mlen as *mut usize,
                    sm.as_ptr(),
                    sm.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_signature(
                    detached_sig.as_mut_ptr(),
                    &mut smlen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );
            assert!(
                smlen <= PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_CRYPTO_BYTES,
                "Signed message length should be ≤ CRYPTO_BYTES"
            );
            assert_eq!(
                0,
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );
            assert!(
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
                    detached_sig.as_ptr(),
                    smlen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                ) < 0
            );

            assert!(
                PQCLEAN_RAINBOWVCCYCLICCOMPRESSED_CLEAN_crypto_sign_verify(
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
