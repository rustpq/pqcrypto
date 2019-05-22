/// Post-Quantum cryptographic primitives
///
/// Packages the [PQClean][pqclean] project as Rust crates
///
/// [pqclean]: https://github.com/PQClean/PQClean/
pub use pqcrypto_traits as traits;

pub mod prelude {
    use pqcrypto_traits::kem::{
        Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
    };
    use pqcrypto_traits::sign::{
        DetachedSignature as _, PublicKey as _, SecretKey as _, SignedMessage as _,
    };
}

pub mod kem {
    pub use pqcrypto_frodo::*;
    pub use pqcrypto_kyber::*;
    pub use pqcrypto_ntru::*;
}

pub mod sign {
    pub use pqcrypto_mqdss::*;
    pub use pqcrypto_sphincsplus::*;
}
