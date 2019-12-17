extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let target_dilithium2_clean_dir = Path::new("pqclean/crypto_sign/dilithium2/clean");
    let scheme_dilithium2_clean_files =
        glob::glob(target_dilithium2_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    #[allow(unused_variables)]
    let target_dilithium2_avx2_dir = Path::new("pqclean/crypto_sign/dilithium2/avx2");
    #[allow(unused_variables)]
    let scheme_dilithium2_avx2_files =
        glob::glob(target_dilithium2_avx2_dir.join("*.[csS]").to_str().unwrap()).unwrap();
    let target_dilithium3_clean_dir = Path::new("pqclean/crypto_sign/dilithium3/clean");
    let scheme_dilithium3_clean_files =
        glob::glob(target_dilithium3_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    #[allow(unused_variables)]
    let target_dilithium3_avx2_dir = Path::new("pqclean/crypto_sign/dilithium3/avx2");
    #[allow(unused_variables)]
    let scheme_dilithium3_avx2_files =
        glob::glob(target_dilithium3_avx2_dir.join("*.[csS]").to_str().unwrap()).unwrap();
    let target_dilithium4_clean_dir = Path::new("pqclean/crypto_sign/dilithium4/clean");
    let scheme_dilithium4_clean_files =
        glob::glob(target_dilithium4_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    #[allow(unused_variables)]
    let target_dilithium4_avx2_dir = Path::new("pqclean/crypto_sign/dilithium4/avx2");
    #[allow(unused_variables)]
    let scheme_dilithium4_avx2_files =
        glob::glob(target_dilithium4_avx2_dir.join("*.[csS]").to_str().unwrap()).unwrap();
    let mut builder = cc::Build::new();
    builder.include("pqclean/common").flag("-std=c99");

    #[cfg(debug_assertions)]
    {
        builder.flag("-g3");
    }
    let common_dir = Path::new("pqclean/common");

    #[allow(unused_variables)]
    let keccak4x_dir = common_dir.join("keccak4x");

    #[allow(unused_mut)]
    let mut common_files = vec![
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
        common_dir.join("sp800-185.c"),
    ];

    #[cfg(all(
        not(disable_avx2),
        not(target_os = "windows"),
        not(target_os = "macos"),
        target_arch = "x86_64"
    ))]
    {
        builder
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-maes")
            .flag("-mpopcnt");
        common_files.push(keccak4x_dir.join("KeccakP-1600-times4-SIMD256.c"));
    }

    builder.files(common_files.into_iter());
    builder.include(target_dilithium2_clean_dir).files(
        scheme_dilithium2_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(
        not(disable_avx2),
        not(target_os = "windows"),
        not(target_os = "macos"),
        target_arch = "x86_64"
    ))]
    {
        builder.include(target_dilithium2_avx2_dir).files(
            scheme_dilithium2_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.include(target_dilithium3_clean_dir).files(
        scheme_dilithium3_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(
        not(disable_avx2),
        not(target_os = "windows"),
        not(target_os = "macos"),
        target_arch = "x86_64"
    ))]
    {
        builder.include(target_dilithium3_avx2_dir).files(
            scheme_dilithium3_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.include(target_dilithium4_clean_dir).files(
        scheme_dilithium4_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(
        not(disable_avx2),
        not(target_os = "windows"),
        not(target_os = "macos"),
        target_arch = "x86_64"
    ))]
    {
        builder.include(target_dilithium4_avx2_dir).files(
            scheme_dilithium4_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.compile("libdilithium.a");

    // Print enableing flag for AVX2 implementation
    #[cfg(all(
        not(disable_avx2),
        not(target_os = "windows"),
        not(target_os = "macos"),
        target_arch = "x86_64"
    ))]
    {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
