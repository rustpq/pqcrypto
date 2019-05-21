//! Provides helper macros to implement the hash functions.

/// Implements a hash function
#[macro_export]
macro_rules! implement_hash {
    ($name: ident, $name_inc_init: ident, $name_inc_blocks: ident, $name_inc_finalize: ident,
     $name_state: ident, $hash: ident, $output_bytes: expr) => {
        /// The state for the hash function
        #[repr(C)]
        pub struct $name_state {
            state: *mut libc::c_void,
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
            let digest = $hash::new()
                .chain(unsafe { std::slice::from_raw_parts(input, inlen as usize) })
                .result();
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
            let hash_state = Box::new($hash::default());
            (*state).state = Box::into_raw(hash_state) as *mut libc::c_void;
        }

        /// Add 64-bytes blocks to the state
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_blocks(
            state: *mut $name_state,
            inblocks: *const libc::uint8_t,
            inlen: libc::size_t,
        ) {
            use digest::Digest;
            let digest = (*state).state as *mut $hash;
            let input: &[u8] = std::slice::from_raw_parts(inblocks, (inlen as usize) * 64);
            (*digest).input(input);
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
            use digest::Digest;
            let digest = std::mem::replace(&mut (*state).state, std::ptr::null_mut());
            let mut digest = Box::from_raw(digest as *mut $hash);
            let input: &[u8] = std::slice::from_raw_parts(inbytes, inlen as usize);
            digest.input(input);
            let mut out_slice = std::slice::from_raw_parts_mut(out, $output_bytes);
            let digest = digest.result();
            (&mut out_slice).copy_from_slice(&digest);
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
            state: *mut libc::c_void,
        }

        /// Incremental XOF state
        #[repr(C)]
        pub enum $inc_state_name {
            Absorb(*mut libc::c_void),
            Squeeze(*mut libc::c_void),
        }

        impl $inc_state_name {
            unsafe fn get_absorb(&self) -> *mut $xof {
                match self {
                    $inc_state_name::Absorb(state) => (*state) as *mut $xof,
                    _ => std::process::abort(),
                }
            }
            unsafe fn get_squeeze(&self) -> *mut Sha3XofReader {
                match self {
                    $inc_state_name::Squeeze(state) => (*state) as *mut Sha3XofReader,
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
            use std::default::Default;
            use digest::{ExtendableOutput, Input, XofReader};
            let input = std::slice::from_raw_parts(input, inlen as usize);
            let output = std::slice::from_raw_parts_mut(output, outlen as usize);
            $xof::default()
                .chain(input)
                .xof_result()
                .read(output);
        }

        /// Initializes the XOF state and absorbs the input
        ///
        /// After calling this function, pass to ``_squeezeblocks``
        #[no_mangle]
        pub unsafe extern "C" fn $name_absorb(state: *mut $state_name, input: *const libc::uint8_t, input_len: libc::size_t) {
            use sha3::digest::{Input, ExtendableOutput};
            let input = std::slice::from_raw_parts(input, input_len as usize);
            let xof_state = Box::into_raw(Box::new($xof::default().chain(input).xof_result())) as *mut libc::c_void;
            (*state).state = xof_state;
        }

        /// Squeeze out output from the XOF which already absorbed things through ``_absorb``.
        #[no_mangle]
        pub unsafe extern "C" fn $name_squeezeblocks(output: *mut libc::uint8_t, nblocks: libc::size_t, state: *mut $state_name) {
            use digest::XofReader;
            let mut output = std::slice::from_raw_parts_mut(output, $rate * nblocks as usize);
            let xofreader = (*state).state as *mut Sha3XofReader;
            (*xofreader).read(&mut output);
        }

        /// Initialize the incremental XOF state
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_init(state: *mut $inc_state_name) {
            let hash_state = Box::new($xof::default());
            (*state) = $inc_state_name::Absorb(Box::into_raw(hash_state) as *mut libc::c_void);
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
            (*digest).input(input);
        }

        /// Finalize the XOF state to prepare for squeezing.
        /// After this you can't absorb anymore.
        #[no_mangle]
        pub unsafe extern "C" fn $name_inc_finalize(state: *mut $inc_state_name) {
            use digest::ExtendableOutput;
            let digest =
                std::mem::replace(&mut (*state).get_absorb(), std::ptr::null_mut()) as *mut $xof;
            let digest = Box::from_raw(digest);
            *state = $inc_state_name::Squeeze(
                Box::into_raw(Box::new(digest.xof_result())) as *mut libc::c_void
            );
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


