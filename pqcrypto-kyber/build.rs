extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let target_kyber512_clean_dir = Path::new("pqclean/crypto_kem/kyber512/clean");
    let scheme_kyber512_clean_files =
        glob::glob(target_kyber512_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber768_clean_dir = Path::new("pqclean/crypto_kem/kyber768/clean");
    let scheme_kyber768_clean_files =
        glob::glob(target_kyber768_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber1024_clean_dir = Path::new("pqclean/crypto_kem/kyber1024/clean");
    let scheme_kyber1024_clean_files =
        glob::glob(target_kyber1024_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let mut builder = cc::Build::new();
    builder.include("pqclean/common").flag("-std=c99");

    #[cfg(debug_assertions)]
    {
        builder.flag("-g3");
    }
    let common_dir = Path::new("pqclean/common");

    let common_files = vec![
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
    ];

    builder.files(common_files.into_iter());
    builder.include(target_kyber512_clean_dir).files(
        scheme_kyber512_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.include(target_kyber768_clean_dir).files(
        scheme_kyber768_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.include(target_kyber1024_clean_dir).files(
        scheme_kyber1024_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.compile("libkyber.a");
}
