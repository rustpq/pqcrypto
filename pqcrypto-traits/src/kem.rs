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

pub trait Ciphertext {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized;
}

pub trait SharedSecret {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized;
}
