extern crate cc;
extern crate glob;

use std::env;
use std::path::{Path, PathBuf};
use std::{fs::File, io::Write};

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
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntrulpr653", "clean"]
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
        builder.compile("ntrulpr653_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntrulpr653", "avx2"]
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
            .compile("ntrulpr653_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntrulpr761", "clean"]
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
        builder.compile("ntrulpr761_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntrulpr761", "avx2"]
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
            .compile("ntrulpr761_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntrulpr857", "clean"]
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
        builder.compile("ntrulpr857_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntrulpr857", "avx2"]
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
            .compile("ntrulpr857_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "sntrup653", "clean"]
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
        builder.compile("sntrup653_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "sntrup653", "avx2"]
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
            .compile("sntrup653_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "sntrup761", "clean"]
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
        builder.compile("sntrup761_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "sntrup761", "avx2"]
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
            .compile("sntrup761_avx2");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "sntrup857", "clean"]
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
        builder.compile("sntrup857_clean");
    }

    if avx2_enabled && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "sntrup857", "avx2"]
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
            .compile("sntrup857_avx2");
    }

    // Print enableing flag for AVX2 implementation
    if avx2_enabled && target_arch == "x86_64" {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
