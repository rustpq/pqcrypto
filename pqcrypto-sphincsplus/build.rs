extern crate cc;
extern crate glob;

use std::env;
use std::path::{Path, PathBuf};

macro_rules! build_clean {
    ($variant:expr) => {
        let internals_include_path = &std::env::var("DEP_PQCRYPTO_INTERNALS_INCLUDEPATH").unwrap();
        let common_dir = Path::new("pqclean/common");

        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", $variant, "clean"]
            .iter()
            .collect();

        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        if target_os == "wasi" {
            let wasi_sdk_path =
                &std::env::var("WASI_SDK_DIR").expect("missing environment variable: WASI_SDK_DIR");
            builder.flag(format!("--sysroot={}", wasi_sdk_path).as_str());
        }

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
        builder.compile(format!("{}_clean", $variant).as_str());
    };
}

macro_rules! build_aesni {
    ($variant:expr) => {
        let internals_include_path = &std::env::var("DEP_PQCRYPTO_INTERNALS_INCLUDEPATH").unwrap();
        let common_dir = Path::new("pqclean/common");

        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", $variant, "aesni"]
            .iter()
            .collect();

        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        if target_os == "wasi" {
            let wasi_sdk_path =
                &std::env::var("WASI_SDK_DIR").expect("missing environment variable: WASI_SDK_DIR");
            builder.flag(format!("--sysroot={}", wasi_sdk_path).as_str());
        }

        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
        if target_env == "msvc" {
            builder.flag("/arch:AVX2");
        } else {
            builder.flag("-maes");
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
        builder.compile(format!("{}_aesni", $variant).as_str());
    };
}

macro_rules! build_avx2 {
    ($variant:expr) => {
        let internals_include_path = &std::env::var("DEP_PQCRYPTO_INTERNALS_INCLUDEPATH").unwrap();
        let common_dir = Path::new("pqclean/common");

        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_sign", $variant, "avx2"]
            .iter()
            .collect();

        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        if target_os == "wasi" {
            let wasi_sdk_path =
                &std::env::var("WASI_SDK_DIR").expect("missing environment variable: WASI_SDK_DIR");
            builder.flag(format!("--sysroot={}", wasi_sdk_path).as_str());
        }

        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
        if target_env == "msvc" {
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
            );
        builder.compile(format!("{}_avx2", $variant).as_str());
    };
}

fn main() {
    #[allow(unused_variables)]
    let aes_enabled = env::var("CARGO_FEATURE_AES").is_ok();
    #[allow(unused_variables)]
    let avx2_enabled = env::var("CARGO_FEATURE_AVX2").is_ok();
    #[allow(unused_variables)]
    let neon_enabled = env::var("CARGO_FEATURE_NEON").is_ok();
    #[allow(unused_variables)]
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    #[allow(unused_variables)]
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    #[allow(unused_variables)]
    let is_windows = target_os == "windows";
    #[allow(unused_variables)]
    let is_macos = target_os == "macos";

    build_clean!("sphincs-haraka-128f-robust");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-128f-robust");
    }
    build_clean!("sphincs-haraka-128f-simple");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-128f-simple");
    }
    build_clean!("sphincs-haraka-128s-robust");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-128s-robust");
    }
    build_clean!("sphincs-haraka-128s-simple");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-128s-simple");
    }
    build_clean!("sphincs-haraka-192f-robust");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-192f-robust");
    }
    build_clean!("sphincs-haraka-192f-simple");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-192f-simple");
    }
    build_clean!("sphincs-haraka-192s-robust");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-192s-robust");
    }
    build_clean!("sphincs-haraka-192s-simple");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-192s-simple");
    }
    build_clean!("sphincs-haraka-256f-robust");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-256f-robust");
    }
    build_clean!("sphincs-haraka-256f-simple");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-256f-simple");
    }
    build_clean!("sphincs-haraka-256s-robust");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-256s-robust");
    }
    build_clean!("sphincs-haraka-256s-simple");
    if target_arch == "x86_64" && aes_enabled {
        build_aesni!("sphincs-haraka-256s-simple");
    }
    build_clean!("sphincs-shake256-128f-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-128f-robust");
    }
    build_clean!("sphincs-shake256-128f-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-128f-simple");
    }
    build_clean!("sphincs-shake256-128s-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-128s-robust");
    }
    build_clean!("sphincs-shake256-128s-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-128s-simple");
    }
    build_clean!("sphincs-shake256-192f-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-192f-robust");
    }
    build_clean!("sphincs-shake256-192f-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-192f-simple");
    }
    build_clean!("sphincs-shake256-192s-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-192s-robust");
    }
    build_clean!("sphincs-shake256-192s-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-192s-simple");
    }
    build_clean!("sphincs-shake256-256f-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-256f-robust");
    }
    build_clean!("sphincs-shake256-256f-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-256f-simple");
    }
    build_clean!("sphincs-shake256-256s-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-256s-robust");
    }
    build_clean!("sphincs-shake256-256s-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-shake256-256s-simple");
    }
    build_clean!("sphincs-sha256-128f-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-128f-robust");
    }
    build_clean!("sphincs-sha256-128f-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-128f-simple");
    }
    build_clean!("sphincs-sha256-128s-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-128s-robust");
    }
    build_clean!("sphincs-sha256-128s-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-128s-simple");
    }
    build_clean!("sphincs-sha256-192f-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-192f-robust");
    }
    build_clean!("sphincs-sha256-192f-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-192f-simple");
    }
    build_clean!("sphincs-sha256-192s-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-192s-robust");
    }
    build_clean!("sphincs-sha256-192s-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-192s-simple");
    }
    build_clean!("sphincs-sha256-256f-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-256f-robust");
    }
    build_clean!("sphincs-sha256-256f-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-256f-simple");
    }
    build_clean!("sphincs-sha256-256s-robust");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-256s-robust");
    }
    build_clean!("sphincs-sha256-256s-simple");
    if target_arch == "x86_64" && avx2_enabled {
        build_avx2!("sphincs-sha256-256s-simple");
    }

    if target_arch == "x86_64" && avx2_enabled {
        // Print enableing flag for AVX2 implementation
        println!("cargo:rustc-cfg=enable_x86_avx2");
    }
    if target_arch == "x86_64" && aes_enabled {
        // Print enableing flag for AES implementation
        println!("cargo:rustc-cfg=enable_x86_aes");
    }
}
