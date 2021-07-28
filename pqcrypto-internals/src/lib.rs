use core::slice;

use getrandom;
use libc;

#[no_mangle]
pub unsafe extern "C" fn PQCRYPTO_RUST_randombytes(buf: *mut u8, len: libc::size_t) {
    let buf = slice::from_raw_parts_mut(buf, len as usize);
    getrandom::getrandom(buf).expect("RNG Failed")
}
