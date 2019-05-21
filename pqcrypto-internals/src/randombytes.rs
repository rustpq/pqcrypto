//! Provides the random number generator

use libc;
use rand::prelude::*;

#[no_mangle]
/// Fills buf with xlen random bytes
pub extern "C" fn randombytes(buf: *mut libc::uint8_t, xlen: libc::size_t) -> libc::c_int {
    let mut buf = unsafe { std::slice::from_raw_parts_mut(buf, xlen as usize) };
    thread_rng().fill_bytes(&mut buf);
    0
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem;

    #[test]
    fn test_randombytes() {
        let mut buf: [libc::uint8_t; 100] = unsafe { mem::uninitialized() };
        randombytes(buf.as_mut_ptr(), 100);
    }
}
