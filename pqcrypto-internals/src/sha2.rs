//! Implements the SHA2 family of hash functions.

use sha2::{Sha224, Sha256, Sha384, Sha512};

implement_hash!(
    sha224,
    sha224_inc_init,
    sha224_inc_blocks,
    sha224_inc_finalize,
    Sha224IncState,
    Sha224,
    224 / 8
);
implement_hash!(
    sha256,
    sha256_inc_init,
    sha256_inc_blocks,
    sha256_inc_finalize,
    Sha256IncState,
    Sha256,
    256 / 8
);
implement_hash!(
    sha384,
    sha384_inc_init,
    sha384_inc_blocks,
    sha384_inc_finalize,
    Sha384IncState,
    Sha384,
    384 / 8
);
implement_hash!(
    sha512,
    sha512_inc_init,
    sha512_inc_blocks,
    sha512_inc_finalize,
    Sha512IncState,
    Sha512,
    512 / 8
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        use digest::Digest;
        let input = b"hello world";
        let mut output = [0u8; 32];
        sha256(
            output.as_mut_ptr() as *mut libc::uint8_t,
            input.as_ptr() as *const libc::uint8_t,
            input.len() as libc::size_t,
        );
        assert_eq!(
            output[..],
            Sha256::digest(input)[..]
        );
    }

    #[test]
    fn test_sha256_inc_api() {
        use digest::Digest;
        let mut state: Sha256IncState = Sha256IncState {
            state: std::ptr::null_mut(),
        };
        let state_ptr = &mut state as *mut Sha256IncState;
        let input = b"hello world";
        let mut output = [0u8; 256 / 8];
        unsafe {
            sha256_inc_init(state_ptr);
            sha256_inc_finalize(
                output.as_mut_ptr() as *mut libc::uint8_t,
                state_ptr,
                input.as_ptr() as *const libc::uint8_t,
                input.len() as libc::size_t,
            );
        }
        assert_eq!(
            output[..],
            Sha256::digest(input)[..]
        );
    }
}
