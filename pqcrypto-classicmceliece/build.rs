extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let common_dir = Path::new("pqclean").join("common");
    let common_files = vec![
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
        common_dir.join("sp800-185.c"),
    ];

    cc::Build::new()
        .flag("-std=c99")
        .include(common_dir)
        .files(common_files.into_iter())
        .compile("pqclean_common");

    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece348864")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece348864")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece348864_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece348864")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece348864_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece348864f")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece348864f")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece348864f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece348864f")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece348864f_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece460896")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece460896")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece460896_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece460896")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece460896_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece460896f")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece460896f")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece460896f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece460896f")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece460896f_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6688128")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6688128")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece6688128_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6688128")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece6688128_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6688128f")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6688128f")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece6688128f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6688128f")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece6688128f_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6960119")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6960119")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece6960119_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6960119")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece6960119_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6960119f")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6960119f")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece6960119f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece6960119f")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece6960119f_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece8192128")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece8192128")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece8192128_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece8192128")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece8192128_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }
    {
        let mut builder = cc::Build::new();
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece8192128f")
            .join("vec");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
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
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece8192128f")
            .join("clean");
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder
            .flag("-std=c99")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile("mceliece8192128f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir = Path::new("pqclean")
            .join("crypto_kem")
            .join("mceliece8192128f")
            .join("avx");
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .flag("-mbmi2")
            .flag("-mbmi")
            .flag("-maes")
            .flag("-mpopcnt")
            .include(common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            )
            .compile("mceliece8192128f_avx");

        cc::Build::new()
            .flag("-std=c99")
            .flag("-mavx2")
            .file(
                common_dir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
    }

    // Print enableing flag for AVX2 implementation
    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
