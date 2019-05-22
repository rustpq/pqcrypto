pub trait PublicKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized;
}

pub trait SecretKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized;
}

pub trait SignedMessage {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized;
}

pub trait DetachedSignature {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized;
}

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
            VerificationError::__NonExhaustive => unreachable!("Should never have been constructed"),
        }
    }
}

impl std::error::Error for VerificationError {}
