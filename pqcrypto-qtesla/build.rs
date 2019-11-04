extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let target_qteslapi_clean_dir = Path::new("pqclean/crypto_sign/qtesla-p-I/clean");
    let scheme_qteslapi_clean_files =
        glob::glob(target_qteslapi_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_qteslapiii_clean_dir = Path::new("pqclean/crypto_sign/qtesla-p-III/clean");
    let scheme_qteslapiii_clean_files =
        glob::glob(target_qteslapiii_clean_dir.join("*.c").to_str().unwrap()).unwrap();
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
    ];

    builder.files(common_files.into_iter());
    builder.include(target_qteslapi_clean_dir).files(
        scheme_qteslapi_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.include(target_qteslapiii_clean_dir).files(
        scheme_qteslapiii_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.compile("libqtesla.a");
}
