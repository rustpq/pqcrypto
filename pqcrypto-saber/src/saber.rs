//! saber
//!
//! These bindings use the clean version from [PQClean][pqc]
//!
//! # Example
//! ```
//! use pqcrypto_saber::saber::*;
//! let (pk, sk) = keypair();
//! let (ss1, ct) = encapsulate(&pk);
//! let ss2 = decapsulate(&ct, &sk);
//! assert!(ss1 == ss2);
//! ```
//!
//! [pqc]: https://github.com/pqclean/pqclean/

// This file is generated.

use crate::ffi;
use pqcrypto_traits::kem as primitive;
use pqcrypto_traits::{Error, Result};

macro_rules! simple_struct {
    ($type: ident, $size: expr) => {
        #[derive(Clone, Copy)]
        pub struct $type([u8; $size]);

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

simple_struct!(PublicKey, ffi::PQCLEAN_SABER_CLEAN_CRYPTO_PUBLICKEYBYTES);
simple_struct!(SecretKey, ffi::PQCLEAN_SABER_CLEAN_CRYPTO_SECRETKEYBYTES);
simple_struct!(Ciphertext, ffi::PQCLEAN_SABER_CLEAN_CRYPTO_CIPHERTEXTBYTES);
simple_struct!(SharedSecret, ffi::PQCLEAN_SABER_CLEAN_CRYPTO_BYTES);

/// Get the number of bytes for a public key
pub const fn public_key_bytes() -> usize {
    ffi::PQCLEAN_SABER_CLEAN_CRYPTO_PUBLICKEYBYTES
}

/// Get the number of bytes for a secret key
pub const fn secret_key_bytes() -> usize {
    ffi::PQCLEAN_SABER_CLEAN_CRYPTO_SECRETKEYBYTES
}

/// Get the number of bytes for the encapsulated ciphertext
pub const fn ciphertext_bytes() -> usize {
    ffi::PQCLEAN_SABER_CLEAN_CRYPTO_CIPHERTEXTBYTES
}

/// Get the number of bytes for the shared secret
pub const fn shared_secret_bytes() -> usize {
    ffi::PQCLEAN_SABER_CLEAN_CRYPTO_BYTES
}

/// Generate a saber keypair
pub fn keypair() -> (PublicKey, SecretKey) {
    #[cfg(enable_avx2)]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { keypair_avx2() };
        }
    }
    keypair_portable()
}

#[inline]
fn keypair_portable() -> (PublicKey, SecretKey) {
    let mut pk = PublicKey::new();
    let mut sk = SecretKey::new();
    assert_eq!(
        unsafe {
            ffi::PQCLEAN_SABER_CLEAN_crypto_kem_keypair(pk.0.as_mut_ptr(), sk.0.as_mut_ptr())
        },
        0
    );
    (pk, sk)
}
#[cfg(enable_avx2)]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn keypair_avx2() -> (PublicKey, SecretKey) {
    let mut pk = PublicKey::new();
    let mut sk = SecretKey::new();
    assert_eq!(
        ffi::PQCLEAN_SABER_AVX2_crypto_kem_keypair(pk.0.as_mut_ptr(), sk.0.as_mut_ptr()),
        0
    );
    (pk, sk)
}

/// Encapsulate to a saber public key
pub fn encapsulate(pk: &PublicKey) -> (SharedSecret, Ciphertext) {
    #[cfg(enable_avx2)]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { encapsulate_avx2(pk) };
        }
    }

    encapsulate_portable(pk)
}

#[inline]
fn encapsulate_portable(pk: &PublicKey) -> (SharedSecret, Ciphertext) {
    let mut ss = SharedSecret::new();
    let mut ct = Ciphertext::new();

    assert_eq!(
        unsafe {
            ffi::PQCLEAN_SABER_CLEAN_crypto_kem_enc(
                ct.0.as_mut_ptr(),
                ss.0.as_mut_ptr(),
                pk.0.as_ptr(),
            )
        },
        0,
    );

    (ss, ct)
}

#[cfg(enable_avx2)]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn encapsulate_avx2(pk: &PublicKey) -> (SharedSecret, Ciphertext) {
    let mut ss = SharedSecret::new();
    let mut ct = Ciphertext::new();

    assert_eq!(
        ffi::PQCLEAN_SABER_AVX2_crypto_kem_enc(ct.0.as_mut_ptr(), ss.0.as_mut_ptr(), pk.0.as_ptr(),),
        0,
    );

    (ss, ct)
}

/// Decapsulate the received saber ciphertext
pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
    #[cfg(enable_avx2)]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { decapsulate_avx2(ct, sk) };
        }
    }
    decapsulate_portable(ct, sk)
}

#[inline]
fn decapsulate_portable(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
    let mut ss = SharedSecret::new();
    assert_eq!(
        unsafe {
            ffi::PQCLEAN_SABER_CLEAN_crypto_kem_dec(ss.0.as_mut_ptr(), ct.0.as_ptr(), sk.0.as_ptr())
        },
        0
    );
    ss
}

#[cfg(enable_avx2)]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn decapsulate_avx2(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
    let mut ss = SharedSecret::new();
    assert_eq!(
        ffi::PQCLEAN_SABER_AVX2_crypto_kem_dec(ss.0.as_mut_ptr(), ct.0.as_ptr(), sk.0.as_ptr(),),
        0
    );
    ss
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_kem() {
        let (pk, sk) = keypair();
        let (ss1, ct) = encapsulate(&pk);
        let ss2 = decapsulate(&ct, &sk);
        assert_eq!(&ss1.0[..], &ss2.0[..], "Difference in shared secrets!");
    }
}
