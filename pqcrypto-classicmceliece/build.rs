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
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864", "vec"]
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
        builder.compile("mceliece348864_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864", "clean"]
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
        builder.compile("mceliece348864_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece348864_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864f", "vec"]
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
        builder.compile("mceliece348864f_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864f", "clean"]
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
        builder.compile("mceliece348864f_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece348864f_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896", "vec"]
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
        builder.compile("mceliece460896_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896", "clean"]
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
        builder.compile("mceliece460896_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece460896_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896f", "vec"]
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
        builder.compile("mceliece460896f_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896f", "clean"]
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
        builder.compile("mceliece460896f_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece460896f_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128", "vec"]
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
        builder.compile("mceliece6688128_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128", "clean"]
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
        builder.compile("mceliece6688128_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece6688128_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128f", "vec"]
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
        builder.compile("mceliece6688128f_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128f", "clean"]
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
        builder.compile("mceliece6688128f_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece6688128f_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119", "vec"]
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
        builder.compile("mceliece6960119_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119", "clean"]
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
        builder.compile("mceliece6960119_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece6960119_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119f", "vec"]
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
        builder.compile("mceliece6960119f_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119f", "clean"]
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
        builder.compile("mceliece6960119f_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece6960119f_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128", "vec"]
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
        builder.compile("mceliece8192128_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128", "clean"]
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
        builder.compile("mceliece8192128_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece8192128_avx");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128f", "vec"]
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
        builder.compile("mceliece8192128f_vec");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128f", "clean"]
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
        builder.compile("mceliece8192128f_clean");
    }

    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();

        if target_arch == "wasm32" {
            builder.flag("--sysroot=../../wasi-sysroot");
        }
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
            .compile("mceliece8192128f_avx");
    }

    // Print enableing flag for AVX2 implementation
    if avx2_enabled && !is_windows && target_arch == "x86_64" {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
