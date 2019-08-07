extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let common_dir = Path::new("pqclean/common");
    let common_files = [
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
    ];

    let target_ledakemlt12_leaktime_dir = Path::new("pqclean/crypto_kem/ledakemlt12/leaktime");
    let scheme_ledakemlt12_leaktime_files = glob::glob(
        target_ledakemlt12_leaktime_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_ledakemlt32_leaktime_dir = Path::new("pqclean/crypto_kem/ledakemlt32/leaktime");
    let scheme_ledakemlt32_leaktime_files = glob::glob(
        target_ledakemlt32_leaktime_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_ledakemlt52_leaktime_dir = Path::new("pqclean/crypto_kem/ledakemlt52/leaktime");
    let scheme_ledakemlt52_leaktime_files = glob::glob(
        target_ledakemlt52_leaktime_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    cc::Build::new()
        .include("pqclean/common")
        .flag("-std=c99")
        .flag("-O3")
        .files(common_files.into_iter())
        .include(target_ledakemlt12_leaktime_dir)
        .files(
            scheme_ledakemlt12_leaktime_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_ledakemlt32_leaktime_dir)
        .files(
            scheme_ledakemlt32_leaktime_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_ledakemlt52_leaktime_dir)
        .files(
            scheme_ledakemlt52_leaktime_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libledacryptkem.a");
}
