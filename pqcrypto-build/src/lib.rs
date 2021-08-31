use core::str;
use std::env;
use std::path::Path;

pub fn new_cc_builder() -> cc::Build {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let mut builder = cc::Build::new();
    if target_arch == "wasm32" {
        if Path::new("../../wasi-sysroot").exists() == false {
            eprintln!("failed to find wasi-sysroot in parent directory");
            std::process::exit(111);
        }
        builder.flag("--sysroot=../../wasi-sysroot");
    }
    builder
}

pub fn pqclean_path() -> &'static str {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    match target_arch.as_str() {
        "wasm32" => "pqclean-wasi",
        _ => "pqclean",
    }
}

pub fn prepare_build_environment() {}
