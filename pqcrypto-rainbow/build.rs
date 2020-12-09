extern crate cc;
extern crate glob;

use std::env;
use std::path::PathBuf;

fn main() {
    let common_dir: PathBuf = ["pqclean", "common"].iter().collect();
    let common_files = vec![
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
        common_dir.join("nistseedexpander.c"),
        common_dir.join("sp800-185.c"),
    ];

    cc::Build::new()
        .include(&common_dir)
        .files(common_files.into_iter())
        .compile("pqclean_common");

    let avx2_enabled = env::var("CARGO_FEATURE_AVX2").is_ok();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let is_windows = target_os == "windows";
    let is_macos = target_os == "macos";

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "rainbowIIIc-classic", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowIIIc-classic_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "rainbowIIIc-cyclic", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowIIIc-cyclic_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "rainbowIIIc-cyclic-compressed",
            "clean",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowIIIc-cyclic-compressed_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "rainbowIa-classic", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowIa-classic_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "rainbowIa-cyclic", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowIa-cyclic_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "rainbowIa-cyclic-compressed",
            "clean",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowIa-cyclic-compressed_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "rainbowVc-classic", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowVc-classic_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "rainbowVc-cyclic", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowVc-cyclic_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "rainbowVc-cyclic-compressed",
            "clean",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("rainbowVc-cyclic-compressed_clean");
    }
}
