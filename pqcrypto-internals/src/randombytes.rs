//! Provides the random number generator

use libc;
use rand::prelude::*;

#[no_mangle]
/// Fills buf with xlen random bytes
pub extern "C" fn randombytes(buf: *mut libc::uint8_t, xlen: libc::size_t) -> libc::c_int {
    let buf = unsafe { std::slice::from_raw_parts_mut(buf, xlen as usize) };
    thread_rng().fill(&mut buf[..]);
    0
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test;
    use std::mem;

    #[test]
    fn test_randombytes() {
        let mut buf = mem::MaybeUninit::<[libc::uint8_t; 100]>::uninit();
        randombytes(buf.as_mut_ptr() as *mut libc::uint8_t, 100);
        unsafe { buf.assume_init() };
    }

    #[bench]
    fn measure_randombytes(b: &mut test::Bencher) {
        let mut buffer = [0u8; 64];
        b.iter(|| randombytes(buffer.as_mut().as_mut_ptr() as *mut libc::uint8_t, 64));
        b.bytes = 64;
    }
}
