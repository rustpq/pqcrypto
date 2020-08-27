extern crate cc;
extern crate glob;

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

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece348864_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece348864_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864f", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece348864f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece348864f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece348864f_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece460896_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece460896_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896f", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece460896f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece460896f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece460896f_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece6688128_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece6688128_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128f", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece6688128f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6688128f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece6688128f_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece6960119_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece6960119_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119f", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece6960119f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece6960119f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece6960119f_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece8192128_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece8192128_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }
    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128f", "vec"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
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
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("mceliece8192128f_clean");
    }

    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "mceliece8192128f", "avx"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.[csS]").to_str().unwrap()).unwrap();
        let mut builder = cc::Build::new();
        #[cfg(windows)]
        {
            builder.flag("/arch:AVX2");
        }
        #[cfg(not(windows))]
        {
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
            .compile("mceliece8192128f_avx");

        #[cfg(not(windows))]
        {
            cc::Build::new()
                .flag("-mavx2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
        #[cfg(windows)]
        {
            cc::Build::new()
                .flag("/arch:AVX2")
                .file(
                    &common_dir
                        .join("keccak4x")
                        .join("KeccakP-1600-times4-SIMD256.c"),
                )
                .compile("keccak4x");
        }
    }

    // Print enableing flag for AVX2 implementation
    #[cfg(all(not(disable_avx2), not(target_os = "windows"), target_arch = "x86_64"))]
    {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
