extern crate cc;
extern crate glob;

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let internals_include_path = &std::env::var("DEP_PQCRYPTO_INTERNALS_INCLUDEPATH").unwrap();
    let common_dir = Path::new("pqclean/common");

    #[allow(unused_variables)]
    let avx2_enabled = env::var("CARGO_FEATURE_AVX2").is_ok();
    #[allow(unused_variables)]
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    #[allow(unused_variables)]
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    #[allow(unused_variables)]
    let is_windows = target_os == "windows";
    #[allow(unused_variables)]
    let is_macos = target_os == "macos";

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-rmrs-128", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("hqc-rmrs-128_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-rmrs-192", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("hqc-rmrs-192_clean");
    }

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "hqc-rmrs-256", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("hqc-rmrs-256_clean");
    }
}
