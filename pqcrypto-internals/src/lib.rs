#![cfg_attr(benchmark,feature(test))]

#![cfg(all(test, benchmark))]
extern crate test;

mod macros;
mod randombytes;
//pub mod fips202;

//pub use randombytes::*;

mod sha2;
