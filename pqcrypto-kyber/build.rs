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

    let target_kyber512_dir = Path::new("pqclean/crypto_kem/kyber512/clean");
    let scheme_kyber512_files =
        glob::glob(target_kyber512_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber768_dir = Path::new("pqclean/crypto_kem/kyber768/clean");
    let scheme_kyber768_files =
        glob::glob(target_kyber768_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber1024_dir = Path::new("pqclean/crypto_kem/kyber1024/clean");
    let scheme_kyber1024_files =
        glob::glob(target_kyber1024_dir.join("*.c").to_str().unwrap()).unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .flag("-O3")
        .files(common_files.into_iter())
        .include(target_kyber512_dir)
        .files(
            scheme_kyber512_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_kyber768_dir)
        .files(
            scheme_kyber768_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_kyber1024_dir)
        .files(
            scheme_kyber1024_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libkyber.a");

    println!("cargo:rustc-link-lib=pqcrypto_internals");
}
