//! sphincs-sha256-128s-robust
//!
//! These bindings use the clean version from [PQClean][pqc]
//!
//! # Example
//! ```
//! use pqcrypto_sphincsplus::sphincssha256128srobust::*;
//! let message = vec![0, 1, 2, 3, 4, 5];
//! let (pk, sk) = keypair();
//! let sm = sign(&message, &sk);
//! let verifiedmsg = open(&sm, &pk).unwrap();
//! assert!(verifiedmsg == message);
//! ```
//!
//! [pqc]: https://github.com/pqclean/pqclean/

// This file is generated.

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

use crate::ffi;
use alloc::vec::Vec;
use pqcrypto_traits::sign as primitive;
use pqcrypto_traits::{Error, Result};

macro_rules! simple_struct {
    ($type: ident, $size: expr) => {
        #[derive(Clone, Copy)]
        #[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
        pub struct $type(
            #[cfg_attr(feature = "serialization", serde(with = "BigArray"))] [u8; $size],
        );

        impl $type {
            /// Generates an uninitialized object
            ///
            /// Used to pass to ``ffi`` interfaces.
            ///
            /// Internal use only!
            fn new() -> Self {
                $type([0u8; $size])
            }
        }

        impl primitive::$type for $type {
            /// Get this object as a byte slice
            #[inline]
            fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Construct this object from a byte slice
            fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $size {
                    Err(Error::BadLength {
                        name: stringify!($type),
                        actual: bytes.len(),
                        expected: $size,
                    })
                } else {
                    let mut array = [0u8; $size];
                    array.copy_from_slice(bytes);
                    Ok($type(array))
                }
            }
        }

        impl PartialEq for $type {
            /// By no means constant time comparison
            fn eq(&self, other: &Self) -> bool {
                self.0
                    .iter()
                    .zip(other.0.iter())
                    .try_for_each(|(a, b)| if a == b { Ok(()) } else { Err(()) })
                    .is_ok()
            }
        }
    };
}

simple_struct!(
    PublicKey,
    ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES
);
simple_struct!(
    SecretKey,
    ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES
);

#[derive(Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DetachedSignature(
    #[cfg_attr(feature = "serialization", serde(with = "BigArray"))]
    [u8; ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES],
    usize,
);

// for internal use
impl DetachedSignature {
    fn new() -> Self {
        DetachedSignature(
            [0u8; ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES],
            0,
        )
    }
}

impl primitive::DetachedSignature for DetachedSignature {
    /// Get this object as a byte slice
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0[..self.1]
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let actual = bytes.len();
        let expected = ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES;
        if actual > expected {
            return Err(Error::BadLength {
                name: "DetachedSignature",
                actual,
                expected,
            });
        }
        let mut array = [0u8; ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES];
        array[..bytes.len()].copy_from_slice(bytes);
        Ok(DetachedSignature(array, actual))
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct SignedMessage(Vec<u8>);
impl primitive::SignedMessage for SignedMessage {
    /// Get this object as a byte slice
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Construct this object from a byte slice
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(SignedMessage(bytes.to_vec()))
    }
}

impl SignedMessage {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Get the number of bytes for a public key
pub const fn public_key_bytes() -> usize {
    ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES
}

/// Get the number of bytes for a secret key
pub const fn secret_key_bytes() -> usize {
    ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES
}

/// Get the number of bytes that a signature occupies
pub const fn signature_bytes() -> usize {
    ffi::PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_CRYPTO_BYTES
}

macro_rules! gen_keypair {
    ($variant:ident) => {{
        let mut pk = PublicKey::new();
        let mut sk = SecretKey::new();
        assert_eq!(
            unsafe { ffi::$variant(pk.0.as_mut_ptr(), sk.0.as_mut_ptr()) },
            0
        );
        (pk, sk)
    }};
}

/// Generate a sphincs-sha256-128s-robust keypair
pub fn keypair() -> (PublicKey, SecretKey) {
    #[cfg(all(enable_x86_avx2, feature = "avx2"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            return gen_keypair!(PQCLEAN_SPHINCSSHA256128SROBUST_AVX2_crypto_sign_keypair);
        }
    }
    gen_keypair!(PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_keypair)
}

macro_rules! gen_signature {
    ($variant:ident, $msg:ident, $sk:ident) => {{
        let max_len = $msg.len() + signature_bytes();
        let mut signed_msg = Vec::with_capacity(max_len);
        let mut smlen: usize = 0;
        unsafe {
            ffi::$variant(
                signed_msg.as_mut_ptr(),
                &mut smlen as *mut usize,
                $msg.as_ptr(),
                $msg.len(),
                $sk.0.as_ptr(),
            );
            debug_assert!(smlen <= max_len, "exceeded vector capacity");
            signed_msg.set_len(smlen);
        }
        SignedMessage(signed_msg)
    }};
}

/// Sign the message and return the signed message.
pub fn sign(msg: &[u8], sk: &SecretKey) -> SignedMessage {
    #[cfg(all(enable_x86_avx2, feature = "avx2"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            return gen_signature!(PQCLEAN_SPHINCSSHA256128SROBUST_AVX2_crypto_sign, msg, sk);
        }
    }
    gen_signature!(PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign, msg, sk)
}

macro_rules! open_signed {
    ($variant:ident, $sm:ident, $pk:ident) => {{
        let mut m: Vec<u8> = Vec::with_capacity($sm.len());
        let mut mlen: usize = 0;
        match unsafe {
            ffi::$variant(
                m.as_mut_ptr(),
                &mut mlen as *mut usize,
                $sm.0.as_ptr(),
                $sm.len(),
                $pk.0.as_ptr(),
            )
        } {
            0 => {
                unsafe { m.set_len(mlen) };
                Ok(m)
            }
            -1 => Err(primitive::VerificationError::InvalidSignature),
            _ => Err(primitive::VerificationError::UnknownVerificationError),
        }
    }};
}

/// Open the signed message and if verification succeeds return the message
pub fn open(
    sm: &SignedMessage,
    pk: &PublicKey,
) -> core::result::Result<Vec<u8>, primitive::VerificationError> {
    #[cfg(all(enable_x86_avx2, feature = "avx2"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            return open_signed!(
                PQCLEAN_SPHINCSSHA256128SROBUST_AVX2_crypto_sign_open,
                sm,
                pk
            );
        }
    }
    open_signed!(
        PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_open,
        sm,
        pk
    )
}

macro_rules! detached_signature {
    ($variant:ident, $msg:ident, $sk:ident) => {{
        let mut sig = DetachedSignature::new();
        unsafe {
            ffi::$variant(
                sig.0.as_mut_ptr(),
                &mut sig.1 as *mut usize,
                $msg.as_ptr(),
                $msg.len(),
                $sk.0.as_ptr(),
            );
        }
        sig
    }};
}

/// Create a detached signature on the message
pub fn detached_sign(msg: &[u8], sk: &SecretKey) -> DetachedSignature {
    #[cfg(all(enable_x86_avx2, feature = "avx2"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            return detached_signature!(
                PQCLEAN_SPHINCSSHA256128SROBUST_AVX2_crypto_sign_signature,
                msg,
                sk
            );
        }
    }
    detached_signature!(
        PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_signature,
        msg,
        sk
    )
}

macro_rules! verify_detached_sig {
    ($variant:ident, $sig:ident, $msg:ident, $pk:ident) => {{
        let res = unsafe {
            ffi::$variant(
                $sig.0.as_ptr(),
                $sig.1,
                $msg.as_ptr(),
                $msg.len(),
                $pk.0.as_ptr(),
            )
        };
        match res {
            0 => Ok(()),
            -1 => Err(primitive::VerificationError::InvalidSignature),
            _ => Err(primitive::VerificationError::UnknownVerificationError),
        }
    }};
}

/// Verify the detached signature
pub fn verify_detached_signature(
    sig: &DetachedSignature,
    msg: &[u8],
    pk: &PublicKey,
) -> core::result::Result<(), primitive::VerificationError> {
    #[cfg(all(enable_x86_avx2, feature = "avx2"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            return verify_detached_sig!(
                PQCLEAN_SPHINCSSHA256128SROBUST_AVX2_crypto_sign_verify,
                sig,
                msg,
                pk
            );
        }
    }
    verify_detached_sig!(
        PQCLEAN_SPHINCSSHA256128SROBUST_CLEAN_crypto_sign_verify,
        sig,
        msg,
        pk
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::prelude::*;

    #[test]
    pub fn test_sign() {
        let mut rng = rand::thread_rng();
        let len: u16 = rng.gen();

        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
        let (pk, sk) = keypair();
        let sm = sign(&message, &sk);
        let verifiedmsg = open(&sm, &pk).unwrap();
        assert!(verifiedmsg == message);
    }

    #[test]
    pub fn test_sign_detached() {
        let mut rng = rand::thread_rng();
        let len: u16 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let (pk, sk) = keypair();
        let sig = detached_sign(&message, &sk);
        assert!(verify_detached_signature(&sig, &message, &pk).is_ok());
        assert!(!verify_detached_signature(&sig, &message[..message.len() - 1], &pk).is_ok());
    }
}
