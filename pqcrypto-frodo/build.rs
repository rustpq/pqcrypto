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

    let target_frodokem640shake_dir = Path::new("pqclean/crypto_kem/frodokem640shake/clean");
    let scheme_frodokem640shake_files =
        glob::glob(target_frodokem640shake_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_frodokem640aes_dir = Path::new("pqclean/crypto_kem/frodokem640aes/clean");
    let scheme_frodokem640aes_files =
        glob::glob(target_frodokem640aes_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_frodokem976aes_dir = Path::new("pqclean/crypto_kem/frodokem976aes/clean");
    let scheme_frodokem976aes_files =
        glob::glob(target_frodokem976aes_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_frodokem976shake_dir = Path::new("pqclean/crypto_kem/frodokem976shake/clean");
    let scheme_frodokem976shake_files =
        glob::glob(target_frodokem976shake_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_frodokem1344aes_dir = Path::new("pqclean/crypto_kem/frodokem1344aes/clean");
    let scheme_frodokem1344aes_files =
        glob::glob(target_frodokem1344aes_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_frodokem1344shake_dir = Path::new("pqclean/crypto_kem/frodokem1344shake/clean");
    let scheme_frodokem1344shake_files =
        glob::glob(target_frodokem1344shake_dir.join("*.c").to_str().unwrap()).unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .flag("-O3")
        .files(common_files.into_iter())
        .include(target_frodokem640shake_dir)
        .files(
            scheme_frodokem640shake_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem640aes_dir)
        .files(
            scheme_frodokem640aes_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem976aes_dir)
        .files(
            scheme_frodokem976aes_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem976shake_dir)
        .files(
            scheme_frodokem976shake_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem1344aes_dir)
        .files(
            scheme_frodokem1344aes_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem1344shake_dir)
        .files(
            scheme_frodokem1344shake_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libfrodo.a");

    println!("cargo:rustc-link-lib=pqcrypto_internals");
}
