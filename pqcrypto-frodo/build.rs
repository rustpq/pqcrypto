extern crate cc;
extern crate glob;

use pqcrypto_build::*;
use std::env;
use std::path::{Path, PathBuf};

fn main() {
    prepare_build_environment();

    let internals_include_path = &std::env::var("DEP_PQCRYPTO_INTERNALS_INCLUDEPATH").unwrap();
    let common_dir: PathBuf = [pqclean_path(), "common"].iter().collect();
    let common_files = vec![
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
        common_dir.join("nistseedexpander.c"),
        common_dir.join("sp800-185.c"),
    ];

    new_cc_builder()
        .include(&common_dir)
        .files(common_files.into_iter())
        .compile("pqclean_common");

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
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem640aes", "opt"]
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
        builder.compile("frodokem640aes_opt");
    }
    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem640aes", "clean"]
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
        builder.compile("frodokem640aes_clean");
    }

    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem640shake", "opt"]
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
        builder.compile("frodokem640shake_opt");
    }
    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem640shake", "clean"]
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
        builder.compile("frodokem640shake_clean");
    }

    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem976aes", "opt"]
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
        builder.compile("frodokem976aes_opt");
    }
    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem976aes", "clean"]
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
        builder.compile("frodokem976aes_clean");
    }

    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem976shake", "opt"]
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
        builder.compile("frodokem976shake_opt");
    }
    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem976shake", "clean"]
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
        builder.compile("frodokem976shake_clean");
    }

    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem1344aes", "opt"]
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
        builder.compile("frodokem1344aes_opt");
    }
    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem1344aes", "clean"]
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
        builder.compile("frodokem1344aes_clean");
    }

    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem1344shake", "opt"]
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
        builder.compile("frodokem1344shake_opt");
    }
    {
        let mut builder = new_cc_builder();
        let target_dir: PathBuf = [pqclean_path(), "crypto_kem", "frodokem1344shake", "clean"]
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
        builder.compile("frodokem1344shake_clean");
    }
}
