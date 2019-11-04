extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let target_firesaber_clean_dir = Path::new("pqclean/crypto_kem/firesaber/clean");
    let scheme_firesaber_clean_files =
        glob::glob(target_firesaber_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_lightsaber_clean_dir = Path::new("pqclean/crypto_kem/lightsaber/clean");
    let scheme_lightsaber_clean_files =
        glob::glob(target_lightsaber_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_saber_clean_dir = Path::new("pqclean/crypto_kem/saber/clean");
    let scheme_saber_clean_files =
        glob::glob(target_saber_clean_dir.join("*.c").to_str().unwrap()).unwrap();
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
        common_dir.join("sp800-185.c"),
    ];

    builder.files(common_files.into_iter());
    builder.include(target_firesaber_clean_dir).files(
        scheme_firesaber_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.include(target_lightsaber_clean_dir).files(
        scheme_lightsaber_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.include(target_saber_clean_dir).files(
        scheme_saber_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.compile("libsaber.a");
}
