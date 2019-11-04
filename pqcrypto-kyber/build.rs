extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let target_kyber512_clean_dir = Path::new("pqclean/crypto_kem/kyber512/clean");
    let scheme_kyber512_clean_files =
        glob::glob(target_kyber512_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber512_avx2_dir = Path::new("pqclean/crypto_kem/kyber512/avx2");
    let scheme_kyber512_avx2_files =
        glob::glob(target_kyber512_avx2_dir.join("*.[csS]").to_str().unwrap()).unwrap();
    let target_kyber768_clean_dir = Path::new("pqclean/crypto_kem/kyber768/clean");
    let scheme_kyber768_clean_files =
        glob::glob(target_kyber768_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber768_avx2_dir = Path::new("pqclean/crypto_kem/kyber768/avx2");
    let scheme_kyber768_avx2_files =
        glob::glob(target_kyber768_avx2_dir.join("*.[csS]").to_str().unwrap()).unwrap();
    let target_kyber1024_clean_dir = Path::new("pqclean/crypto_kem/kyber1024/clean");
    let scheme_kyber1024_clean_files =
        glob::glob(target_kyber1024_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber1024_avx2_dir = Path::new("pqclean/crypto_kem/kyber1024/avx2");
    let scheme_kyber1024_avx2_files =
        glob::glob(target_kyber1024_avx2_dir.join("*.[csS]").to_str().unwrap()).unwrap();
    let target_kyber51290s_clean_dir = Path::new("pqclean/crypto_kem/kyber512-90s/clean");
    let scheme_kyber51290s_clean_files =
        glob::glob(target_kyber51290s_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber51290s_avx2_dir = Path::new("pqclean/crypto_kem/kyber512-90s/avx2");
    let scheme_kyber51290s_avx2_files = glob::glob(
        target_kyber51290s_avx2_dir
            .join("*.[csS]")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_kyber76890s_clean_dir = Path::new("pqclean/crypto_kem/kyber768-90s/clean");
    let scheme_kyber76890s_clean_files =
        glob::glob(target_kyber76890s_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber76890s_avx2_dir = Path::new("pqclean/crypto_kem/kyber768-90s/avx2");
    let scheme_kyber76890s_avx2_files = glob::glob(
        target_kyber76890s_avx2_dir
            .join("*.[csS]")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_kyber102490s_clean_dir = Path::new("pqclean/crypto_kem/kyber1024-90s/clean");
    let scheme_kyber102490s_clean_files =
        glob::glob(target_kyber102490s_clean_dir.join("*.c").to_str().unwrap()).unwrap();
    let target_kyber102490s_avx2_dir = Path::new("pqclean/crypto_kem/kyber1024-90s/avx2");
    let scheme_kyber102490s_avx2_files = glob::glob(
        target_kyber102490s_avx2_dir
            .join("*.[csS]")
            .to_str()
            .unwrap(),
    )
    .unwrap();
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
    ];

    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    {
        builder.flag("-mavx2").flag("-mbmi2").flag("-mpopcnt");
        common_files.push(keccak4x_dir.join("KeccakP-1600-times4-SIMD256.c"));
    }

    builder.files(common_files.into_iter());
    builder.include(target_kyber512_clean_dir).files(
        scheme_kyber512_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    {
        builder.include(target_kyber512_avx2_dir).files(
            scheme_kyber512_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.include(target_kyber768_clean_dir).files(
        scheme_kyber768_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    {
        builder.include(target_kyber768_avx2_dir).files(
            scheme_kyber768_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.include(target_kyber1024_clean_dir).files(
        scheme_kyber1024_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    {
        builder.include(target_kyber1024_avx2_dir).files(
            scheme_kyber1024_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.include(target_kyber51290s_clean_dir).files(
        scheme_kyber51290s_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    {
        builder.include(target_kyber51290s_avx2_dir).files(
            scheme_kyber51290s_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.include(target_kyber76890s_clean_dir).files(
        scheme_kyber76890s_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    {
        builder.include(target_kyber76890s_avx2_dir).files(
            scheme_kyber76890s_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.include(target_kyber102490s_clean_dir).files(
        scheme_kyber102490s_clean_files
            .into_iter()
            .map(|p| p.unwrap().to_string_lossy().into_owned()),
    );
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    {
        builder.include(target_kyber102490s_avx2_dir).files(
            scheme_kyber102490s_avx2_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    }
    builder.compile("libkyber.a");
}
