/// Supporting Traits for the pqcrypto crates.

/// Convenience wrapper for Result
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that may arise when constructing keys or signatures.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    BadLength {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
    #[doc(hidden)]
    __NonExhaustive,
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
            Error::__NonExhaustive => unreachable!("Should never be constructed"),
        }
    }
}

impl std::error::Error for Error {}

pub mod kem;
pub mod sign;
