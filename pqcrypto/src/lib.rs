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
    #[cfg(feature = "pqcrypto-mlkem")]
    pub use pqcrypto_mlkem::{mlkem1024, mlkem512, mlkem768};
}

pub mod sign {
    #[cfg(feature = "pqcrypto-falcon")]
    pub use pqcrypto_falcon::{falcon1024, falcon512, falconpadded1024, falconpadded512};
    #[cfg(feature = "pqcrypto-mldsa")]
    pub use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
    #[cfg(feature = "pqcrypto-sphincsplus")]
    pub use pqcrypto_sphincsplus::{
        sphincssha2128fsimple, sphincssha2128ssimple, sphincssha2192fsimple, sphincssha2192ssimple,
        sphincssha2256fsimple, sphincssha2256ssimple, sphincsshake128fsimple,
        sphincsshake128ssimple, sphincsshake192fsimple, sphincsshake192ssimple,
        sphincsshake256fsimple, sphincsshake256ssimple,
    };
}
