extern crate cc;
extern crate glob;

use std::path::Path;


fn main() {
    let common_dir = Path::new("pqclean/common");
    let common_files = [
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("randombytes.c"),
        common_dir.join("sha2.c"),
    ];

    let target_sphincsshake256128fsimple_dir = Path::new("pqclean/crypto_sign/sphincs-shake256-128f-simple/clean");
    let scheme_sphincsshake256128fsimple_files = glob::glob(target_sphincsshake256128fsimple_dir.join("*.c").to_str().unwrap()).unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .files(common_files.into_iter())
        .include(target_sphincsshake256128fsimple_dir)
        .files(scheme_sphincsshake256128fsimple_files.into_iter().map(|p| p.unwrap().to_string_lossy().into_owned()))
        .compile("libsphincsplus.a");

}