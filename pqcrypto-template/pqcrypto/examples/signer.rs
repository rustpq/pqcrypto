use std::fs::{self, File};
use std::io::prelude::*;

use pqcrypto::prelude::*;
use pqcrypto::sign::mldsa44::*;

fn parseargs() -> (String, String, String) {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        panic!("Usage: {} sk in out", args[0]);
    }
    (args[1].clone(), args[2].clone(), args[3].clone())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk_filename, in_filename, sig_filename) = parseargs();
    let mut sigfile= File::create(sig_filename)?;

    let sk = SecretKey::from_bytes(&fs::read(sk_filename)?)?;
    let signature = detached_sign(&fs::read(in_filename)?, &sk);

    sigfile.write_all(signature.as_bytes())?;

    Ok(())
}
