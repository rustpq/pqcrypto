//! Supporting Traits for the pqcrypto crates.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

/// Convenience wrapper for Result
pub type Result<T> = core::result::Result<T, Error>;

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

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
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

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub mod kem;
pub mod sign;
