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
    pub use pqcrypto_hqc::{hqcrmrs128, hqcrmrs192, hqcrmrs256};
    #[cfg(feature = "pqcrypto-kyber")]
    pub use pqcrypto_kyber::{
        kyber1024, kyber102490s, kyber512, kyber51290s, kyber768, kyber76890s,
    };
}

pub mod sign {
    #[cfg(feature = "pqcrypto-dilithium")]
    pub use pqcrypto_dilithium::{
        dilithium2, dilithium2aes, dilithium3, dilithium3aes, dilithium5, dilithium5aes,
    };
    #[cfg(feature = "pqcrypto-falcon")]
    pub use pqcrypto_falcon::{falcon1024, falcon512};
    #[cfg(feature = "pqcrypto-sphincsplus")]
    pub use pqcrypto_sphincsplus::{
        sphincsharaka128frobust, sphincsharaka128fsimple, sphincsharaka128srobust,
        sphincsharaka128ssimple, sphincsharaka192frobust, sphincsharaka192fsimple,
        sphincsharaka192srobust, sphincsharaka192ssimple, sphincsharaka256frobust,
        sphincsharaka256fsimple, sphincsharaka256srobust, sphincsharaka256ssimple,
        sphincssha2128frobust, sphincssha2128fsimple, sphincssha2128srobust, sphincssha2128ssimple,
        sphincssha2192frobust, sphincssha2192fsimple, sphincssha2192srobust, sphincssha2192ssimple,
        sphincssha2256frobust, sphincssha2256fsimple, sphincssha2256srobust, sphincssha2256ssimple,
        sphincsshake128frobust, sphincsshake128fsimple, sphincsshake128srobust,
        sphincsshake128ssimple, sphincsshake192frobust, sphincsshake192fsimple,
        sphincsshake192srobust, sphincsshake192ssimple, sphincsshake256frobust,
        sphincsshake256fsimple, sphincsshake256srobust, sphincsshake256ssimple,
    };
}
