/// Traits for signature schemes
use crate::Result;

/// A public key for a signature scheme
pub trait PublicKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// A secret key for a signature scheme
pub trait SecretKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// A signed message.
///
/// This object contains both the signed message and the signature on it.
pub trait SignedMessage {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// A detached signature
///
/// This signature does not include the message it certifies; this means that to verify it you also
/// need the message.
///
/// If you can get away with it, use the SignedMessage API, which ensures you won't use the message
/// before having authenticated it.
pub trait DetachedSignature {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// Errors that may arise when verifying a signature
#[derive(Clone, Copy, Debug)]
pub enum VerificationError {
    InvalidSignature,
    UnknownVerificationError,
    __NonExhaustive,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match self {
            VerificationError::InvalidSignature => write!(f, "error: verification failed"),
            VerificationError::UnknownVerificationError => write!(f, "unknown error"),
            VerificationError::__NonExhaustive => {
                unreachable!("Should never have been constructed")
            }
        }
    }
}

impl std::error::Error for VerificationError {}
