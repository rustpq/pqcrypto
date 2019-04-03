extern crate cc;
extern crate glob;

use std::path::Path;


fn main() {
    let target_dir = Path::new("pqclean/crypto_kem/kyber768/clean");
    let common_dir = Path::new("pqclean/common");
    let common_files = [
        common_dir.join("fips202.c"),
        common_dir.join("notrandombytes.c"),
        common_dir.join("sha2.c"),
    ];

    let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .include(target_dir)
        .files(common_files.into_iter())
        .files(scheme_files.into_iter().map(|p| p.unwrap().to_string_lossy().into_owned()))
        .compile("libkyber768.a");
}
