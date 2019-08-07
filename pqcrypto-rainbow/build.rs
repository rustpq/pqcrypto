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

    let target_rainbowcclassic_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowIIIc-classic/clean");
    let scheme_rainbowcclassic_clean_files = glob::glob(
        target_rainbowcclassic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowccyclic_clean_dir = Path::new("pqclean/crypto_sign/rainbowIIIc-cyclic/clean");
    let scheme_rainbowccyclic_clean_files = glob::glob(
        target_rainbowccyclic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowccycliccompressed_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowIIIc-cyclic-compressed/clean");
    let scheme_rainbowccycliccompressed_clean_files = glob::glob(
        target_rainbowccycliccompressed_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowaclassic_clean_dir = Path::new("pqclean/crypto_sign/rainbowIa-classic/clean");
    let scheme_rainbowaclassic_clean_files = glob::glob(
        target_rainbowaclassic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowacyclic_clean_dir = Path::new("pqclean/crypto_sign/rainbowIa-cyclic/clean");
    let scheme_rainbowacyclic_clean_files = glob::glob(
        target_rainbowacyclic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowacycliccompressed_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowIa-cyclic-compressed/clean");
    let scheme_rainbowacycliccompressed_clean_files = glob::glob(
        target_rainbowacycliccompressed_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowcclassic_clean_dir = Path::new("pqclean/crypto_sign/rainbowVc-classic/clean");
    let scheme_rainbowcclassic_clean_files = glob::glob(
        target_rainbowcclassic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowccyclic_clean_dir = Path::new("pqclean/crypto_sign/rainbowVc-cyclic/clean");
    let scheme_rainbowccyclic_clean_files = glob::glob(
        target_rainbowccyclic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowccycliccompressed_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowVc-cyclic-compressed/clean");
    let scheme_rainbowccycliccompressed_clean_files = glob::glob(
        target_rainbowccycliccompressed_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .flag("-O3")
        .files(common_files.into_iter())
        .include(target_rainbowcclassic_clean_dir)
        .files(
            scheme_rainbowcclassic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowccyclic_clean_dir)
        .files(
            scheme_rainbowccyclic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowccycliccompressed_clean_dir)
        .files(
            scheme_rainbowccycliccompressed_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowaclassic_clean_dir)
        .files(
            scheme_rainbowaclassic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowacyclic_clean_dir)
        .files(
            scheme_rainbowacyclic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowacycliccompressed_clean_dir)
        .files(
            scheme_rainbowacycliccompressed_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowcclassic_clean_dir)
        .files(
            scheme_rainbowcclassic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowccyclic_clean_dir)
        .files(
            scheme_rainbowccyclic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowccycliccompressed_clean_dir)
        .files(
            scheme_rainbowccycliccompressed_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("librainbow.a");
}
