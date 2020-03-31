//! Provides helper macros to implement the hash functions.

/// Implements a hash function
#[macro_export]
macro_rules! implement_hash {
    (
        $name: ident,
        $name_inc_init: ident,
        $name_inc_blocks: ident,
        $name_inc_finalize: ident,
        $name_inc_ctx_clone: ident,
        $name_inc_ctx_release: ident,
        $name_state: ident,
        $hash: ident,
        $output_bytes: expr,
        $block_size: expr,
        $test_mod: ident $(,)?
    ) => {
        /// The state for the hash function
        #[repr(C)]
        #[derive(Clone)]
        pub struct $name_state {
            state: Option<$hash>,
        }

        /// Directly obtain the digest of input
        #[no_mangle]
        pub extern "C" fn $name(
            out: *mut libc::uint8_t,
            input: *const libc::uint8_t,
            inlen: libc::size_t,
        ) {
            use digest::Digest;
            let mut out_slice = unsafe { std::slice::from_raw_parts_mut(out, $output_bytes) };
            let input = unsafe { std::slice::from_raw_parts(input, inlen as usize) };
            let digest = $hash::digest(input);
            (&mut out_slice).copy_from_slice(&digest);
        }

        /// Initializes the incremental hashing state.
        ///
        /// Allocates the state for the hash function.
        /// Make sure to call the ``_inc_finalize`` variant
        /// at some point to free the allocated memory.
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_init(state: *mut $name_state) {
            use std::default::Default;
            (*state).state = Some($hash::default());
        }

        /// Add 64-bytes blocks to the state
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_blocks(
            state: *mut $name_state,
            inblocks: *const libc::uint8_t,
            inlen: libc::size_t,
        ) {
            use digest::Digest;
            let digest = (*state).state.as_mut().unwrap();
            let input: &[u8] = std::slice::from_raw_parts(inblocks, (inlen as usize) * $block_size);
            (digest).input(input);
        }

        /// Finalize the state and obtain the hash result.
        ///
        /// Consumes the state
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_finalize(
            out: *mut libc::uint8_t,
            state: *mut $name_state,
            inbytes: *const libc::uint8_t,
            inlen: libc::size_t,
        ) {
            let mut state = std::ptr::read(state);
            use digest::Digest;
            let mut digest = state.state.take().unwrap();
            let input: &[u8] = std::slice::from_raw_parts(inbytes, inlen as usize);
            digest.input(input);
            let mut out_slice = std::slice::from_raw_parts_mut(out, $output_bytes);
            let digest = digest.result();
            (&mut out_slice).copy_from_slice(&digest);
        }

        /// Clone the state of the digest
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_ctx_clone(
            stateout: *mut $name_state,
            statein: *const $name_state,
        ) {
            std::ptr::write(stateout, (*statein).clone());
        }

        /// Drop a state
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_ctx_release(state: *mut $name_state) {
            std::ptr::drop_in_place(state);
        }

        #[cfg(test)]
        mod $test_mod {
            use super::*;
            use test;

            /// Test copying and releasing the copy.
            ///
            /// Should probably be run with Valgrind
            #[test]
            fn test_copy_release() {
                let mut state = $name_state { state: None };
                let state_ptr = &mut state as *mut $name_state;
                let mut state_copy = std::mem::MaybeUninit::<$name_state>::uninit();
                unsafe {
                    $name_inc_init(state_ptr);
                    $name_inc_ctx_clone(state_copy.as_mut_ptr(), state_ptr);
                    let mut state_copy = state_copy.assume_init();
                    // We're explicitly dropping this one
                    $name_inc_ctx_release(&mut state_copy as *mut $name_state);
                    std::mem::forget(state_copy);
                };
            }

            #[bench]
            fn measure_hash(b: &mut test::Bencher) {
                let input = [0u8; 128];
                let mut output = std::mem::MaybeUninit::<[libc::uint8_t; 100]>::uninit();
                b.iter(|| {
                    $name(
                        output.as_mut_ptr() as *mut libc::uint8_t,
                        input.as_ref().as_ptr() as *const libc::uint8_t,
                        128,
                    )
                });
                b.bytes = 128;
            }

            #[bench]
            fn measure_hash_inc(b: &mut test::Bencher) {
                let input = [0u8; 64];
                let mut output = [0u8; 100];
                let input_ptr = input.as_ref().as_ptr() as *const libc::uint8_t;
                let output_ptr = output.as_mut().as_mut_ptr() as *mut libc::uint8_t;
                b.iter(|| unsafe {
                    let mut inc_state = $name_state { state: None };
                    let state_ptr = &mut inc_state as *mut $name_state;
                    $name_inc_init(state_ptr);
                    $name_inc_blocks(state_ptr, input_ptr, 1);
                    $name_inc_finalize(output_ptr, state_ptr, input_ptr, 64);
                    // already dropped
                    std::mem::forget(inc_state);
                });
                b.bytes = 128;
            }
        }
    };
}

/// Implements a XOF
#[macro_export]
macro_rules! implement_xof {
    ($xof: ident, $rate: expr, $name: ident, $name_absorb: ident, $name_squeezeblocks: ident, $name_inc_new: ident, $name_inc_init: ident, $name_inc_absorb: ident, $name_inc_finalize: ident, $name_inc_squeeze: ident, $state_name: ident, $inc_state_name: ident $(,)?) => {
        /// XOF state for the ``_absorb`` and ``_squeezeblocks`` functions.
        #[repr(C)]
        pub struct $state_name {
            reader: Sha3XofReader,
        }

        /// Incremental XOF state
        #[repr(C)]
        pub enum $inc_state_name {
            Absorb($xof),
            Squeeze(Sha3XofReader),
        }

        impl $inc_state_name {
            unsafe fn get_absorb(&mut self) -> &mut $xof {
                match self {
                    $inc_state_name::Absorb(ref mut state) => state,
                    _ => std::process::abort(),
                }
            }
            unsafe fn get_squeeze(&mut self) -> &mut Sha3XofReader {
                match self {
                    $inc_state_name::Squeeze(ref mut reader) => reader,
                    _ => std::process::abort(),
                }
            }
        }

        /// Extendible-Output Function
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            output: *mut libc::uint8_t,
            outlen: libc::size_t,
            input: *const libc::uint8_t,
            inlen: libc::size_t,
        ) {
            use digest::{ExtendableOutput, Input, XofReader};
            use std::default::Default;
            let input = std::slice::from_raw_parts(input, inlen as usize);
            let output = std::slice::from_raw_parts_mut(output, outlen as usize);
            $xof::default().chain(input).xof_result().read(output);
        }

        /// Initializes the XOF state and absorbs the input
        ///
        /// After calling this function, pass to ``_squeezeblocks``
        #[no_mangle]
        pub unsafe extern "C" fn $name_absorb(
            state: *mut $state_name,
            input: *const libc::uint8_t,
            input_len: libc::size_t,
        ) {
            use sha3::digest::{ExtendableOutput, Input};
            let input = std::slice::from_raw_parts(input, input_len as usize);
            let xof_state = $xof::default().chain(input).xof_result();
            (*state).reader = xof_state;
        }

        /// Squeeze out output from the XOF which already absorbed things through ``_absorb``.
        #[no_mangle]
        pub unsafe extern "C" fn $name_squeezeblocks(
            output: *mut libc::uint8_t,
            nblocks: libc::size_t,
            state: *mut $state_name,
        ) {
            use digest::XofReader;
            let mut output = std::slice::from_raw_parts_mut(output, $rate * nblocks as usize);
            (*state).reader.read(&mut output);
        }

        /// Initialize the incremental XOF state
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_init(state: *mut $inc_state_name) {
            (*state) = $inc_state_name::Absorb($xof::default());
        }

        /// Absorb ``input`` into the XOF state
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_absorb(
            state: *mut $inc_state_name,
            input: *const libc::uint8_t,
            inlen: libc::size_t,
        ) {
            use sha2::digest::Input;
            let digest = (*state).get_absorb();
            let input: &[u8] = std::slice::from_raw_parts(input, inlen as usize);
            digest.input(input);
        }

        /// Finalize the XOF state to prepare for squeezing.
        /// After this you can't absorb anymore.
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_finalize(state: *mut $inc_state_name) {
            use digest::ExtendableOutput;
            *state = $inc_state_name::Squeeze((*state).get_absorb().clone().xof_result());
        }

        /// Squeeze out ``outlen`` bytes
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_squeeze(
            output: *mut libc::uint8_t,
            outlen: libc::size_t,
            state: *mut $inc_state_name,
        ) {
            use digest::XofReader;
            let reader = (*state).get_squeeze();
            let output = std::slice::from_raw_parts_mut(output, outlen as usize);
            (*reader).read(output);
        }
    };
}
