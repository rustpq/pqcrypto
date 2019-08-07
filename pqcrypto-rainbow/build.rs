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

    let target_rainbowiiicclassic_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowIIIc-classic/clean");
    let scheme_rainbowiiicclassic_clean_files = glob::glob(
        target_rainbowiiicclassic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowiiiccyclic_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowIIIc-cyclic/clean");
    let scheme_rainbowiiiccyclic_clean_files = glob::glob(
        target_rainbowiiiccyclic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowiiiccycliccompressed_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowIIIc-cyclic-compressed/clean");
    let scheme_rainbowiiiccycliccompressed_clean_files = glob::glob(
        target_rainbowiiiccycliccompressed_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowiaclassic_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowIa-classic/clean");
    let scheme_rainbowiaclassic_clean_files = glob::glob(
        target_rainbowiaclassic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowiacyclic_clean_dir = Path::new("pqclean/crypto_sign/rainbowIa-cyclic/clean");
    let scheme_rainbowiacyclic_clean_files = glob::glob(
        target_rainbowiacyclic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowiacycliccompressed_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowIa-cyclic-compressed/clean");
    let scheme_rainbowiacycliccompressed_clean_files = glob::glob(
        target_rainbowiacycliccompressed_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowvcclassic_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowVc-classic/clean");
    let scheme_rainbowvcclassic_clean_files = glob::glob(
        target_rainbowvcclassic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowvccyclic_clean_dir = Path::new("pqclean/crypto_sign/rainbowVc-cyclic/clean");
    let scheme_rainbowvccyclic_clean_files = glob::glob(
        target_rainbowvccyclic_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_rainbowvccycliccompressed_clean_dir =
        Path::new("pqclean/crypto_sign/rainbowVc-cyclic-compressed/clean");
    let scheme_rainbowvccycliccompressed_clean_files = glob::glob(
        target_rainbowvccycliccompressed_clean_dir
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
        .include(target_rainbowiiicclassic_clean_dir)
        .files(
            scheme_rainbowiiicclassic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowiiiccyclic_clean_dir)
        .files(
            scheme_rainbowiiiccyclic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowiiiccycliccompressed_clean_dir)
        .files(
            scheme_rainbowiiiccycliccompressed_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowiaclassic_clean_dir)
        .files(
            scheme_rainbowiaclassic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowiacyclic_clean_dir)
        .files(
            scheme_rainbowiacyclic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowiacycliccompressed_clean_dir)
        .files(
            scheme_rainbowiacycliccompressed_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowvcclassic_clean_dir)
        .files(
            scheme_rainbowvcclassic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowvccyclic_clean_dir)
        .files(
            scheme_rainbowvccyclic_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_rainbowvccycliccompressed_clean_dir)
        .files(
            scheme_rainbowvccycliccompressed_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("librainbow.a");
}
