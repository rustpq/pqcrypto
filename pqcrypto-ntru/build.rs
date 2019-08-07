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

    let target_ntruhps2048509_clean_dir = Path::new("pqclean/crypto_kem/ntruhps2048509/clean");
    let scheme_ntruhps2048509_clean_files = glob::glob(
        target_ntruhps2048509_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_ntruhps2048677_clean_dir = Path::new("pqclean/crypto_kem/ntruhps2048677/clean");
    let scheme_ntruhps2048677_clean_files = glob::glob(
        target_ntruhps2048677_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_ntruhps4096821_clean_dir = Path::new("pqclean/crypto_kem/ntruhps4096821/clean");
    let scheme_ntruhps4096821_clean_files = glob::glob(
        target_ntruhps4096821_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_ntruhrss701_clean_dir = Path::new("pqclean/crypto_kem/ntruhrss701/clean");
    let scheme_ntruhrss701_clean_files =
        glob::glob(target_ntruhrss701_clean_dir.join("*.c").to_str().unwrap()).unwrap();
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
        .include(target_ntruhps2048509_clean_dir)
        .files(
            scheme_ntruhps2048509_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_ntruhps2048677_clean_dir)
        .files(
            scheme_ntruhps2048677_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_ntruhps4096821_clean_dir)
        .files(
            scheme_ntruhps4096821_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_ntruhrss701_clean_dir)
        .files(
            scheme_ntruhrss701_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libntru.a");
}
