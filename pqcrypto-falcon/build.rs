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

    let target_falcon512_clean_dir = Path::new("pqclean/crypto_sign/falcon-512/clean");
    let scheme_falcon512_clean_files =
        glob::glob(target_falcon512_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_falcon1024_clean_dir = Path::new("pqclean/crypto_sign/falcon-1024/clean");
    let scheme_falcon1024_clean_files =
        glob::glob(target_falcon1024_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .flag("-O3")
        .files(common_files.into_iter())
        .include(target_falcon512_clean_dir)
        .files(
            scheme_falcon512_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_falcon1024_clean_dir)
        .files(
            scheme_falcon1024_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libfalcon.a");
}
