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
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-128-1-cca2", "leaktime"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("hqc-128-1-cca2_leaktime");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-192-1-cca2", "leaktime"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("hqc-192-1-cca2_leaktime");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-192-2-cca2", "leaktime"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("hqc-192-2-cca2_leaktime");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-256-1-cca2", "leaktime"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("hqc-256-1-cca2_leaktime");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-256-2-cca2", "leaktime"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("hqc-256-2-cca2_leaktime");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-256-3-cca2", "leaktime"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("hqc-256-3-cca2_leaktime");
    }
}
