extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let target_newhope1024cpa_clean_dir = Path::new("pqclean/crypto_kem/newhope1024cpa/clean");
    let scheme_newhope1024cpa_clean_files = glob::glob(
        target_newhope1024cpa_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_newhope1024cca_clean_dir = Path::new("pqclean/crypto_kem/newhope1024cca/clean");
    let scheme_newhope1024cca_clean_files = glob::glob(
        target_newhope1024cca_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_newhope512cpa_clean_dir = Path::new("pqclean/crypto_kem/newhope512cpa/clean");
    let scheme_newhope512cpa_clean_files =
        glob::glob(target_newhope512cpa_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_newhope512cca_clean_dir = Path::new("pqclean/crypto_kem/newhope512cca/clean");
    let scheme_newhope512cca_clean_files =
        glob::glob(target_newhope512cca_clean_dir.join("*.c").to_str().unwrap()).unwrap();
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
    builder.include(target_newhope1024cpa_clean_dir).files(
        scheme_newhope1024cpa_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.include(target_newhope1024cca_clean_dir).files(
        scheme_newhope1024cca_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.include(target_newhope512cpa_clean_dir).files(
        scheme_newhope512cpa_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.include(target_newhope512cca_clean_dir).files(
        scheme_newhope512cca_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    builder.compile("libnewhope.a");
}
