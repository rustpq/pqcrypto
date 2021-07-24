extern crate cc;
extern crate glob;

use pqcrypto_build::*;
use std::env;
use std::path::PathBuf;

fn main() {
    prepare_build_environment();

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
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "ntruhps2048509", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("ntruhps2048509_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "ntruhps2048509", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = new_cc_builder();

        if is_windows {
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
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("ntruhps2048509_avx2");

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
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "ntruhps2048677", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("ntruhps2048677_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "ntruhps2048677", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = new_cc_builder();

        if is_windows {
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
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("ntruhps2048677_avx2");

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
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "ntruhps4096821", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("ntruhps4096821_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "ntruhps4096821", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = new_cc_builder();

        if is_windows {
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
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("ntruhps4096821_avx2");

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
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "ntruhrss701", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("ntruhrss701_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "ntruhrss701", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = new_cc_builder();

        if is_windows {
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
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("ntruhrss701_avx2");

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
    if avx2_enabled && target_arch == "x86_64" {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
