use std::fs;

use pqcrypto::prelude::*;
use pqcrypto::sign::sphincsharaka128frobust::*;

fn parseargs() -> (String, String, String) {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        panic!("Usage: {} pk msg sig", args[0]);
    }
    (args[1].clone(), args[2].clone(), args[3].clone())
}

fn main() -> Result<(), Box<std::error::Error>> {
    let (pk_filename, in_filename, sig_filename) = parseargs();
    let pk = PublicKey::from_bytes(&fs::read(pk_filename)?)?;
    let msg = &fs::read(in_filename)?;
    let sig = DetachedSignature::from_bytes(&fs::read(sig_filename)?)?;

    if let Ok(()) = verify_detached_signature(&sig, msg, &pk) {
        println!("Verification success!");
    } else {
        println!("Verification failed!");
    }

    Ok(())
}
