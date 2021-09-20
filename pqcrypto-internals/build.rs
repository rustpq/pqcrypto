extern crate cc;

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

    cc::Build::new()
        .include(&includepath)
        .files(common_files.into_iter())
        .compile("pqclean_common");

    if cfg!(target_arch = "x86") || cfg!(target_arch = "x86_64") {
        let mut builder = cc::Build::new();
        if cfg!(target_env = "msvc") {
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
        println!("cargo:rustc-link-lib=keccak4x");
    }

    println!("cargo:rustc-link-lib=pqclean_common");
}
