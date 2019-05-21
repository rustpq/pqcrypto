//! Implements the FIPS202 standard functions

use sha3::{Sha3_256, Sha3_512, Shake128, Shake256, Sha3XofReader};

implement_hash!(
    sha3_256,
    sha3_256_inc_init,
    sha3_256_inc_absorb,
    sha3_256_inc_finalize,
    Sha3256IncState,
    Sha3_256,
    256 / 8
);
implement_hash!(
    sha3_512,
    sha3_512_inc_init,
    sha3_512_inc_absorb,
    sha3_512_inc_finalize,
    Sha3512IncState,
    Sha3_512,
    512 / 8
);


implement_xof!(
    Shake128,
    168,
    shake128,
    shake128_squeeze,
    shake128_absorb,
    shake128_inc_new,
    shake128_inc_init,
    shake128_inc_absorb,
    shake128_inc_finalize,
    shake128_inc_squeeze,
    Shake128State,
    Shake128IncState,
);
implement_xof!(
    Shake256,
    136,
    shake256,
    shake256_squeeze,
    shake256_absorb,
    shake256_inc_new,
    shake256_inc_init,
    shake256_inc_absorb,
    shake256_inc_finalize,
    shake256_inc_squeeze,
    Shake256State,
    Shake256IncState,
);

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{digest::ExtendableOutput, digest::Input, Shake128};

    #[test]
    fn test_shake128_inc_api() {
        use digest::XofReader;

        let mut state: Shake128IncState = Shake128IncState::Absorb(std::ptr::null_mut());
        let state_ptr = &mut state as *mut Shake128IncState;
        let input = b"hello world";
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];
        let mut output3 = [0u8; 32];
        unsafe {
            shake128_inc_init(state_ptr);
            shake128_inc_absorb(
                state_ptr,
                input.as_ptr() as *const libc::uint8_t,
                input.len() as libc::size_t,
            );
            shake128_inc_finalize(state_ptr);
            shake128_inc_squeeze(
                output1.as_mut_ptr() as *mut libc::uint8_t,
                output1.len() as libc::size_t,
                state_ptr,
            );
            shake128(
                output2.as_mut_ptr() as *mut libc::uint8_t,
                output2.len() as libc::size_t,
                input.as_ptr() as *const libc::uint8_t,
                input.len() as libc::size_t,
            );
        }
        assert_eq!(output1, output2);

        Shake128::default()
            .chain(&input)
            .xof_result()
            .read(&mut output3);
        assert_eq!(output1, output3);
    }
}
