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
        common_dir.join("sp800-185.c"),
    ];

    cc::Build::new()
        .include(&common_dir)
        .files(common_files.into_iter())
        .compile("pqclean_common");

    {
        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntruhps2048509", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("ntruhps2048509_clean");
    }

    #[cfg(all(not(disable_avx2), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntruhps2048509", "avx2"]
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
            .compile("ntruhps2048509_avx2");

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
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntruhps2048677", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("ntruhps2048677_clean");
    }

    #[cfg(all(not(disable_avx2), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntruhps2048677", "avx2"]
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
            .compile("ntruhps2048677_avx2");

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
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntruhps4096821", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("ntruhps4096821_clean");
    }

    #[cfg(all(not(disable_avx2), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntruhps4096821", "avx2"]
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
            .compile("ntruhps4096821_avx2");

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
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntruhrss701", "clean"]
            .iter()
            .collect();
        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
        builder.include(&common_dir).include(target_dir).files(
            scheme_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
        builder.compile("ntruhrss701_clean");
    }

    #[cfg(all(not(disable_avx2), target_arch = "x86_64"))]
    {
        let target_dir: PathBuf = ["pqclean", "crypto_kem", "ntruhrss701", "avx2"]
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
            .compile("ntruhrss701_avx2");

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
    #[cfg(all(not(disable_avx2), target_arch = "x86_64"))]
    {
        println!("cargo:rustc-cfg=enable_avx2");
    }
}
