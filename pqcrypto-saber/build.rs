extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let common_dir = Path::new("pqclean/common");
    let common_files = [
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
    ];

    let target_firesaber_dir = Path::new("pqclean/crypto_kem/firesaber/clean");
    let scheme_firesaber_files =
        glob::glob(target_firesaber_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_lightsaber_dir = Path::new("pqclean/crypto_kem/lightsaber/clean");
    let scheme_lightsaber_files =
        glob::glob(target_lightsaber_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_saber_dir = Path::new("pqclean/crypto_kem/saber/clean");
    let scheme_saber_files = glob::glob(target_saber_dir.join("*.c").to_str().unwrap()).unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .flag("-O3")
        .files(common_files.into_iter())
        .include(target_firesaber_dir)
        .files(
            scheme_firesaber_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_lightsaber_dir)
        .files(
            scheme_lightsaber_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_saber_dir)
        .files(
            scheme_saber_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libsaber.a");
}
