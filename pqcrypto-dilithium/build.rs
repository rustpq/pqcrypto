extern crate cc;
extern crate glob;

use pqcrypto_build::*;
use std::env;
use std::path::{Path, PathBuf};

fn main() {
    prepare_build_environment();

    let internals_include_path = &std::env::var("DEP_PQCRYPTO_INTERNALS_INCLUDEPATH").unwrap();
    let common_dir: PathBuf = [pqclean_path(), "common"].iter().collect();
    let common_files = vec![
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
        common_dir.join("nistseedexpander.c"),
        common_dir.join("sp800-185.c"),
    ];

    new_cc_builder()
        .include(&common_dir)
        .files(common_files.into_iter())
        .compile("pqclean_common");

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
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_sign", "dilithium2", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("dilithium2_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = [pqclean_path(), "crypto_sign", "dilithium2", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = new_cc_builder();

        if cfg!(target_env = "msvc") {
            builder.flag("/arch:AVX2");
        } else {
            builder
                .flag("-mavx2")
                .flag("-mbmi2")
                .flag("-mbmi")
                .flag("-maes")
                .flag("-mpopcnt")
                .flag("-mpclmul");
        }
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("dilithium2_avx2");

        let mut builder = new_cc_builder();
        if is_windows {
            builder.flag("/arch:AVX2");
        } else {
            builder.flag("-mavx2");
        };
        builder
            .file(
                &common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_sign", "dilithium3", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("dilithium3_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = [pqclean_path(), "crypto_sign", "dilithium3", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = new_cc_builder();

        if cfg!(target_env = "msvc") {
            builder.flag("/arch:AVX2");
        } else {
            builder
                .flag("-mavx2")
                .flag("-mbmi2")
                .flag("-mbmi")
                .flag("-maes")
                .flag("-mpopcnt")
                .flag("-mpclmul");
        }
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("dilithium3_avx2");

        let mut builder = new_cc_builder();
        if is_windows {
            builder.flag("/arch:AVX2");
        } else {
            builder.flag("-mavx2");
        };
        builder
            .file(
                &common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_sign", "dilithium5", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("dilithium5_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = [pqclean_path(), "crypto_sign", "dilithium5", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = new_cc_builder();

        if cfg!(target_env = "msvc") {
            builder.flag("/arch:AVX2");
        } else {
            builder
                .flag("-mavx2")
                .flag("-mbmi2")
                .flag("-mbmi")
                .flag("-maes")
                .flag("-mpopcnt")
                .flag("-mpclmul");
        }
        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("dilithium5_avx2");

        let mut builder = new_cc_builder();
        if is_windows {
            builder.flag("/arch:AVX2");
        } else {
            builder.flag("-mavx2");
        };
        builder
            .file(
                &common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }

    // Print enableing flag for AVX2 implementation
    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
