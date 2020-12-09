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
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "dilithium2", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("dilithium2_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "dilithium2", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if is_windows {
            builder.flag("/arch:AVX2");
        } else {
            builder
                .flag("-mavx2")
                .flag("-mbmi2")
                .flag("-mbmi")
                .flag("-maes")
                .flag("-mpopcnt");
        }
        builder
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("dilithium2_avx2");

        let mut builder = cc::Build::new();
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
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "dilithium3", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("dilithium3_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "dilithium3", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if is_windows {
            builder.flag("/arch:AVX2");
        } else {
            builder
                .flag("-mavx2")
                .flag("-mbmi2")
                .flag("-mbmi")
                .flag("-maes")
                .flag("-mpopcnt");
        }
        builder
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("dilithium3_avx2");

        let mut builder = cc::Build::new();
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
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "dilithium4", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("dilithium4_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_sign", "dilithium4", "avx2"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if is_windows {
            builder.flag("/arch:AVX2");
        } else {
            builder
                .flag("-mavx2")
                .flag("-mbmi2")
                .flag("-mbmi")
                .flag("-maes")
                .flag("-mpopcnt");
        }
        builder
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("dilithium4_avx2");

        let mut builder = cc::Build::new();
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
