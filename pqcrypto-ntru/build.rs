extern crate cc;
extern crate glob;

use std::path::Path;


fn main() {
    let common_dir = Path::new("pqclean/common");
    let common_files = [
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
    ];

    let target_ntruhps2048509_dir = Path::new("pqclean/crypto_kem/ntruhps2048509/clean");
    let scheme_ntruhps2048509_files = glob::glob(target_ntruhps2048509_dir.join("*.c").to_str().unwrap()).unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .files(common_files.into_iter())
        .include(target_ntruhps2048509_dir)
        .files(scheme_ntruhps2048509_files.into_iter().map(|p| p.unwrap().to_string_lossy().into_owned()))
        .compile("libntru.a");

    println!("cargo:rustc-link-lib=pqcrypto_internals");
}