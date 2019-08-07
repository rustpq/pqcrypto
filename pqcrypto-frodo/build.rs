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

    let target_frodokem640shake_opt_dir = Path::new("pqclean/crypto_kem/frodokem640shake/opt");
    let scheme_frodokem640shake_opt_files = glob::glob(
        target_frodokem640shake_opt_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_frodokem640shake_clean_dir = Path::new("pqclean/crypto_kem/frodokem640shake/clean");
    let scheme_frodokem640shake_clean_files = glob::glob(
        target_frodokem640shake_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_frodokem640aes_opt_dir = Path::new("pqclean/crypto_kem/frodokem640aes/opt");
    let scheme_frodokem640aes_opt_files =
        glob::glob(target_frodokem640aes_opt_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_frodokem640aes_clean_dir = Path::new("pqclean/crypto_kem/frodokem640aes/clean");
    let scheme_frodokem640aes_clean_files = glob::glob(
        target_frodokem640aes_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_frodokem976aes_opt_dir = Path::new("pqclean/crypto_kem/frodokem976aes/opt");
    let scheme_frodokem976aes_opt_files =
        glob::glob(target_frodokem976aes_opt_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_frodokem976aes_clean_dir = Path::new("pqclean/crypto_kem/frodokem976aes/clean");
    let scheme_frodokem976aes_clean_files = glob::glob(
        target_frodokem976aes_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_frodokem976shake_opt_dir = Path::new("pqclean/crypto_kem/frodokem976shake/opt");
    let scheme_frodokem976shake_opt_files = glob::glob(
        target_frodokem976shake_opt_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_frodokem976shake_clean_dir = Path::new("pqclean/crypto_kem/frodokem976shake/clean");
    let scheme_frodokem976shake_clean_files = glob::glob(
        target_frodokem976shake_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_frodokem1344aes_opt_dir = Path::new("pqclean/crypto_kem/frodokem1344aes/opt");
    let scheme_frodokem1344aes_opt_files =
        glob::glob(target_frodokem1344aes_opt_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_frodokem1344aes_clean_dir = Path::new("pqclean/crypto_kem/frodokem1344aes/clean");
    let scheme_frodokem1344aes_clean_files = glob::glob(
        target_frodokem1344aes_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_frodokem1344shake_opt_dir = Path::new("pqclean/crypto_kem/frodokem1344shake/opt");
    let scheme_frodokem1344shake_opt_files = glob::glob(
        target_frodokem1344shake_opt_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_frodokem1344shake_clean_dir =
        Path::new("pqclean/crypto_kem/frodokem1344shake/clean");
    let scheme_frodokem1344shake_clean_files = glob::glob(
        target_frodokem1344shake_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let mut builder = cc::Build::new();
    builder
        .include("pqclean/common")
        .flag("-std=c99")
        .flag("-O3");
    #[cfg(debug_assertions)]
    {
        builder.flag("-g3");
    }
    builder
        .files(common_files.into_iter())
        .include(target_frodokem640shake_opt_dir)
        .files(
            scheme_frodokem640shake_opt_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem640shake_clean_dir)
        .files(
            scheme_frodokem640shake_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem640aes_opt_dir)
        .files(
            scheme_frodokem640aes_opt_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem640aes_clean_dir)
        .files(
            scheme_frodokem640aes_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem976aes_opt_dir)
        .files(
            scheme_frodokem976aes_opt_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem976aes_clean_dir)
        .files(
            scheme_frodokem976aes_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem976shake_opt_dir)
        .files(
            scheme_frodokem976shake_opt_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem976shake_clean_dir)
        .files(
            scheme_frodokem976shake_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem1344aes_opt_dir)
        .files(
            scheme_frodokem1344aes_opt_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem1344aes_clean_dir)
        .files(
            scheme_frodokem1344aes_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem1344shake_opt_dir)
        .files(
            scheme_frodokem1344shake_opt_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_frodokem1344shake_clean_dir)
        .files(
            scheme_frodokem1344shake_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libfrodo.a");
}
