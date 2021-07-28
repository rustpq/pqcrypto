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
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-128f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-128f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-128f-robust",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-128f-robust_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-128f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-128f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-128f-simple",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-128f-simple_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-128s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-128s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-128s-robust",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-128s-robust_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-128s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-128s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-128s-simple",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-128s-simple_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-192f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-192f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-192f-robust",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-192f-robust_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-192f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-192f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-192f-simple",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-192f-simple_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-192s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-192s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-192s-robust",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-192s-robust_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-192s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-192s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-192s-simple",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-192s-simple_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-256f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-256f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-256f-robust",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-256f-robust_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-256f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-256f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-256f-simple",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-256f-simple_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-256s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-256s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-256s-robust",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-256s-robust_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-256s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-haraka-256s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-haraka-256s-simple",
            "aesni",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-haraka-256s-simple_aesni");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-128f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-128f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-128f-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-128f-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-128f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-128f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-128f-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-128f-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-128s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-128s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-128s-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-128s-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-128s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-128s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-128s-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-128s-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-192f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-192f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-192f-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-192f-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-192f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-192f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-192f-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-192f-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-192s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-192s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-192s-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-192s-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-192s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-192s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-192s-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-192s-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-256f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-256f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-256f-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-256f-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-256f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-256f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-256f-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-256f-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-256s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-256s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-256s-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-256s-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-256s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-shake256-256s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-shake256-256s-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-shake256-256s-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-128f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-128f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-128f-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-128f-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-128f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-128f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-128f-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-128f-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-128s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-128s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-128s-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-128s-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-128s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-128s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-128s-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-128s-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-192f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-192f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-192f-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-192f-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-192f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-192f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-192f-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-192f-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-192s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-192s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-192s-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-192s-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-192s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-192s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-192s-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-192s-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-256f-robust",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-256f-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-256f-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-256f-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-256f-simple",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-256f-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-256f-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-256f-simple_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-256s-robust",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-256s-robust_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-256s-robust",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-256s-robust_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-256s-simple",
            "clean",
        ]
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
        builder.compile("sphincs-sha256-256s-simple_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = [
            "pqclean",
            "crypto_sign",
            "sphincs-sha256-256s-simple",
            "avx2",
        ]
        .iter()
        .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

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
            .compile("sphincs-sha256-256s-simple_avx2");
    }

    // Print enableing flag for AVX2 implementation
    if avx2_enabled && target_arch == "x86_64" {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
