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

    let target_mqdss48_clean_dir = Path::new("pqclean/crypto_sign/mqdss-48/clean");
    let scheme_mqdss48_clean_files =
        glob::glob(target_mqdss48_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_mqdss64_clean_dir = Path::new("pqclean/crypto_sign/mqdss-64/clean");
    let scheme_mqdss64_clean_files =
        glob::glob(target_mqdss64_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .flag("-O3")
        .files(common_files.into_iter())
        .include(target_mqdss48_clean_dir)
        .files(
            scheme_mqdss48_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_mqdss64_clean_dir)
        .files(
            scheme_mqdss64_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libmqdss.a");
}
