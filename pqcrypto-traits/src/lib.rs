/// Supporting Traits for the pqcrypto crates.

/// Convenience wrapper for Result
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that may arise when constructing keys or signatures.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Error {
    BadLength {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::BadLength {
                name,
                actual,
                expected,
            } => write!(
                f,
                "error: {} expected {} bytes, got {}",
                name, actual, expected
            ),
        }
    }
}

impl std::error::Error for Error {}

pub mod kem;
pub mod sign;
