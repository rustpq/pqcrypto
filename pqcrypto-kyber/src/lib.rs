//! Kyber 768
//!
//! Kyber is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the
//! hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one
//! of the candidate algorithms submitted to the NIST post-quantum cryptography project. The
//! submission lists three different parameter sets aiming at different security levels.
//! Specifically, Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 aims at
//! security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to
//! AES-256.
//!
//! https://pq-crystals.org/kyber/
//!
//! # Examples
//! ```
//! use pqcrypto_kyber::*;
//! let (pk, sk) = keygen();
//! let (ss1, ct) = encapsulate(pk);
//! let ss2 = decapsulate(ct, sk);
//! assert!(ss1 == ss2);
//! ```

use std::mem;

pub mod ffi;
use pqcrypto_traits::kem;

macro_rules! simple_struct {
    ($type: ident, $size: expr) => {
        pub struct $type([u8; $size]);

        impl $type {
            /// Generates an uninitialized object
            ///
            /// Used to pass to ``ffi`` interfaces.
            ///
            /// Internal use only!
            fn new() -> Self {
                $type(unsafe { mem::uninitialized() })
            }
        }

        impl kem::$type for $type {
            /// Get this object as a byte slice
            #[inline]
            fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Construct this object from a byte slice
            fn from_bytes(bytes: &[u8]) -> Self {
                let mut array: [u8; $size] = unsafe { mem::uninitialized() };
                array.copy_from_slice(bytes);
                $type(array)
            }
        }

        impl PartialEq for $type {
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

simple_struct!(PublicKey, ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES);
simple_struct!(SecretKey, ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES);
simple_struct!(
    Ciphertext,
    ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES
);
simple_struct!(SharedSecret, ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES);

pub const fn public_key_bytes() -> usize {
    ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES
}

pub const fn secret_key_bytes() -> usize {
    ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES
}

pub const fn ciphertext_bytes() -> usize {
    ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES
}

pub const fn shared_secret_bytes() -> usize {
    ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES
}

pub fn keygen() -> (PublicKey, SecretKey) {
    let mut pk = PublicKey::new();
    let mut sk = SecretKey::new();
    assert_eq!(
        unsafe {
            ffi::PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk.0.as_mut_ptr(), sk.0.as_mut_ptr())
        },
        0
    );
    (pk, sk)
}

pub fn encapsulate(pk: PublicKey) -> (SharedSecret, Ciphertext) {
    let mut ss = SharedSecret::new();
    let mut ct = Ciphertext::new();

    assert_eq!(
        unsafe {
            ffi::PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(
                ct.0.as_mut_ptr(),
                ss.0.as_mut_ptr(),
                pk.0.as_ptr(),
            )
        },
        0,
    );

    (ss, ct)
}

pub fn decapsulate(ct: Ciphertext, sk: SecretKey) -> SharedSecret {
    let mut ss = SharedSecret::new();
    assert_eq!(
        unsafe {
            ffi::PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(
                ss.0.as_mut_ptr(),
                ct.0.as_ptr(),
                sk.0.as_ptr(),
            )
        },
        0
    );
    ss
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_kem() {
        let (pk, sk) = keygen();
        let (ss1, ct) = encapsulate(pk);
        let ss2 = decapsulate(ct, sk);
        assert!(ss1.0 == ss2.0, "Difference in shared secrets!");
    }
}
