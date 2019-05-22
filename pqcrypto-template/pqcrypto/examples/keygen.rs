use std::fs::File;
use std::io::prelude::*;

use pqcrypto::prelude::*;
use pqcrypto::sign::sphincsharaka128frobust::*;


fn main() -> std::io::Result<()> {
    let mut pubfile = File::create("publickey.bin")?;
    let mut secfile = File::create("secretkey.bin")?;
    let (pk, sk) = keypair();
    pubfile.write_all(pk.as_bytes())?;
    secfile.write_all(sk.as_bytes())?;
    Ok(())
}
