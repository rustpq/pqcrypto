/// Post-Quantum cryptographic primitives
///
/// Packages the [PQClean][pqclean] project as Rust crates
///
/// [pqclean]: https://github.com/PQClean/PQClean/
pub use pqcrypto_traits as traits;

pub mod prelude {
    pub use pqcrypto_traits::kem::{
        Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
    };
    pub use pqcrypto_traits::sign::{
        DetachedSignature as _, PublicKey as _, SecretKey as _, SignedMessage as _,
    };
}

pub mod kem {
    #[cfg(feature = "pqcrypto-classicmceliece")]
    pub use pqcrypto_classicmceliece::{
        mceliece348864, mceliece348864f, mceliece460896, mceliece460896f, mceliece6688128,
        mceliece6688128f, mceliece6960119, mceliece6960119f, mceliece8192128, mceliece8192128f,
    };
    #[cfg(feature = "pqcrypto-hqc")]
    pub use pqcrypto_hqc::{hqc128, hqc192, hqc256};
    #[cfg(feature = "pqcrypto-kyber")]
    pub use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
}

pub mod sign {
    #[cfg(feature = "pqcrypto-dilithium")]
    pub use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
    #[cfg(feature = "pqcrypto-falcon")]
    pub use pqcrypto_falcon::{falcon1024, falcon512};
    #[cfg(feature = "pqcrypto-sphincsplus")]
    pub use pqcrypto_sphincsplus::{
        sphincssha2128fsimple, sphincssha2128ssimple, sphincssha2192fsimple, sphincssha2192ssimple,
        sphincssha2256fsimple, sphincssha2256ssimple, sphincsshake128fsimple,
        sphincsshake128ssimple, sphincsshake192fsimple, sphincsshake192ssimple,
        sphincsshake256fsimple, sphincsshake256ssimple,
    };
}
