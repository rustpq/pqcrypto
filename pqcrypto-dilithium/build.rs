extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let target_dilithium2_clean_dir = Path::new("pqclean/crypto_sign/dilithium2/clean");
    let scheme_dilithium2_clean_files =
        glob::glob(target_dilithium2_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_dilithium3_clean_dir = Path::new("pqclean/crypto_sign/dilithium3/clean");
    let scheme_dilithium3_clean_files =
        glob::glob(target_dilithium3_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_dilithium4_clean_dir = Path::new("pqclean/crypto_sign/dilithium4/clean");
    let scheme_dilithium4_clean_files =
        glob::glob(target_dilithium4_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let mut builder = cc::Build::new();
    builder.include("pqclean/common").flag("-std=c99");

    #[cfg(debug_assertions)]
    {
        builder.flag("-g3");
    }
    let common_dir = Path::new("pqclean/common");
    let common_files = [
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
    ];

    builder
        .files(common_files.into_iter())
        .include(target_dilithium2_clean_dir)
        .files(
            scheme_dilithium2_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_dilithium3_clean_dir)
        .files(
            scheme_dilithium3_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_dilithium4_clean_dir)
        .files(
            scheme_dilithium4_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libdilithium.a");
}
