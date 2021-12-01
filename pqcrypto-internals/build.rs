extern crate cc;

use std::env;
use std::path::Path;

fn main() {
    let includepath = Path::new("include").canonicalize().unwrap();
    println!("cargo:includepath={}", includepath.to_str().unwrap());

    let cfiledir = Path::new("cfiles");
    let common_files = vec![
        cfiledir.join("fips202.c"),
        cfiledir.join("aes.c"),
        cfiledir.join("sha2.c"),
        cfiledir.join("nistseedexpander.c"),
        cfiledir.join("sp800-185.c"),
    ];

    let mut build = cc::Build::new();

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "wasi" {
        let wasi_sdk_path =
            &std::env::var("WASI_SDK_DIR").expect("missing environment variable: WASI_SDK_DIR");
        build.flag(format!("--sysroot={}", wasi_sdk_path).as_str());
    }

    build
        .include(&includepath)
        .files(common_files.into_iter())
        .compile("pqclean_common");
    println!("cargo:rustc-link-lib=pqclean_common");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "x86" || target_arch == "x86_64" {
        let mut builder = cc::Build::new();

        if target_os == "wasi" {
            let wasi_sdk_path =
                &std::env::var("WASI_SDK_DIR").expect("missing environment variable: WASI_SDK_DIR");
            builder.flag(format!("--sysroot={}", wasi_sdk_path).as_str());
        }

        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        if target_os == "windows" {
            builder.flag("/arch:AVX2");
        } else {
            builder.flag("-mavx2");
        };
        builder
            .file(
                &cfiledir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
        println!("cargo:rustc-link-lib=keccak4x")
    }
}
