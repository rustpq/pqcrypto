//! Provides the random number generator

use libc;
use rand::prelude::*;

#[no_mangle]
/// Fills buf with xlen random bytes
pub unsafe extern "C" fn randombytes(buf: *mut libc::uint8_t, xlen: libc::size_t) -> libc::c_int {
    let mut buf = std::slice::from_raw_parts_mut(buf, xlen as usize);
    thread_rng().fill_bytes(&mut buf);
    0
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_randombytes() {
        unsafe {
            let mut buf = [0u8 as libc::uint8_t; 100];
            randombytes(buf.as_mut_ptr(), 100);
        }
    }
}
