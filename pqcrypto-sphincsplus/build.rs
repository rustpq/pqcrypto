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

    let target_sphincsharaka128ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-128s-simple/clean");
    let scheme_sphincsharaka128ssimple_files = glob::glob(
        target_sphincsharaka128ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka128srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-128s-robust/clean");
    let scheme_sphincsharaka128srobust_files = glob::glob(
        target_sphincsharaka128srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka128fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-128f-simple/clean");
    let scheme_sphincsharaka128fsimple_files = glob::glob(
        target_sphincsharaka128fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka128frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-128f-robust/clean");
    let scheme_sphincsharaka128frobust_files = glob::glob(
        target_sphincsharaka128frobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka192ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-192s-simple/clean");
    let scheme_sphincsharaka192ssimple_files = glob::glob(
        target_sphincsharaka192ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka192srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-192s-robust/clean");
    let scheme_sphincsharaka192srobust_files = glob::glob(
        target_sphincsharaka192srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka192fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-192f-simple/clean");
    let scheme_sphincsharaka192fsimple_files = glob::glob(
        target_sphincsharaka192fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka192frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-192f-robust/clean");
    let scheme_sphincsharaka192frobust_files = glob::glob(
        target_sphincsharaka192frobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka256ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-256s-simple/clean");
    let scheme_sphincsharaka256ssimple_files = glob::glob(
        target_sphincsharaka256ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka256srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-256s-robust/clean");
    let scheme_sphincsharaka256srobust_files = glob::glob(
        target_sphincsharaka256srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka256fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-256f-simple/clean");
    let scheme_sphincsharaka256fsimple_files = glob::glob(
        target_sphincsharaka256fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka256frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-256f-robust/clean");
    let scheme_sphincsharaka256frobust_files = glob::glob(
        target_sphincsharaka256frobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256128ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-128s-simple/clean");
    let scheme_sphincsshake256128ssimple_files = glob::glob(
        target_sphincsshake256128ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256128srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-128s-robust/clean");
    let scheme_sphincsshake256128srobust_files = glob::glob(
        target_sphincsshake256128srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256128fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-128f-simple/clean");
    let scheme_sphincsshake256128fsimple_files = glob::glob(
        target_sphincsshake256128fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256128frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-128f-robust/clean");
    let scheme_sphincsshake256128frobust_files = glob::glob(
        target_sphincsshake256128frobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256192ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-192s-simple/clean");
    let scheme_sphincsshake256192ssimple_files = glob::glob(
        target_sphincsshake256192ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256192srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-192s-robust/clean");
    let scheme_sphincsshake256192srobust_files = glob::glob(
        target_sphincsshake256192srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256192fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-192f-simple/clean");
    let scheme_sphincsshake256192fsimple_files = glob::glob(
        target_sphincsshake256192fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256192frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-192f-robust/clean");
    let scheme_sphincsshake256192frobust_files = glob::glob(
        target_sphincsshake256192frobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256256ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-256s-simple/clean");
    let scheme_sphincsshake256256ssimple_files = glob::glob(
        target_sphincsshake256256ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256256srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-256s-robust/clean");
    let scheme_sphincsshake256256srobust_files = glob::glob(
        target_sphincsshake256256srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256256fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-256f-simple/clean");
    let scheme_sphincsshake256256fsimple_files = glob::glob(
        target_sphincsshake256256fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256256frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-256f-robust/clean");
    let scheme_sphincsshake256256frobust_files = glob::glob(
        target_sphincsshake256256frobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256128ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-128s-simple/clean");
    let scheme_sphincssha256128ssimple_files = glob::glob(
        target_sphincssha256128ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256128srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-128s-robust/clean");
    let scheme_sphincssha256128srobust_files = glob::glob(
        target_sphincssha256128srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256128fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-128f-simple/clean");
    let scheme_sphincssha256128fsimple_files = glob::glob(
        target_sphincssha256128fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256128frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-128f-robust/clean");
    let scheme_sphincssha256128frobust_files = glob::glob(
        target_sphincssha256128frobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256192ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-192s-simple/clean");
    let scheme_sphincssha256192ssimple_files = glob::glob(
        target_sphincssha256192ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256192srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-192s-robust/clean");
    let scheme_sphincssha256192srobust_files = glob::glob(
        target_sphincssha256192srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256192fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-192f-simple/clean");
    let scheme_sphincssha256192fsimple_files = glob::glob(
        target_sphincssha256192fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256192frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-192f-robust/clean");
    let scheme_sphincssha256192frobust_files = glob::glob(
        target_sphincssha256192frobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256256ssimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-256s-simple/clean");
    let scheme_sphincssha256256ssimple_files = glob::glob(
        target_sphincssha256256ssimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256256srobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-256s-robust/clean");
    let scheme_sphincssha256256srobust_files = glob::glob(
        target_sphincssha256256srobust_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256256fsimple_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-256f-simple/clean");
    let scheme_sphincssha256256fsimple_files = glob::glob(
        target_sphincssha256256fsimple_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256256frobust_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-256f-robust/clean");
    let scheme_sphincssha256256frobust_files = glob::glob(
        target_sphincssha256256frobust_dir
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
        .include(target_sphincsharaka128ssimple_dir)
        .files(
            scheme_sphincsharaka128ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka128srobust_dir)
        .files(
            scheme_sphincsharaka128srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka128fsimple_dir)
        .files(
            scheme_sphincsharaka128fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka128frobust_dir)
        .files(
            scheme_sphincsharaka128frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka192ssimple_dir)
        .files(
            scheme_sphincsharaka192ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka192srobust_dir)
        .files(
            scheme_sphincsharaka192srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka192fsimple_dir)
        .files(
            scheme_sphincsharaka192fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka192frobust_dir)
        .files(
            scheme_sphincsharaka192frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka256ssimple_dir)
        .files(
            scheme_sphincsharaka256ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka256srobust_dir)
        .files(
            scheme_sphincsharaka256srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka256fsimple_dir)
        .files(
            scheme_sphincsharaka256fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsharaka256frobust_dir)
        .files(
            scheme_sphincsharaka256frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256128ssimple_dir)
        .files(
            scheme_sphincsshake256128ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256128srobust_dir)
        .files(
            scheme_sphincsshake256128srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256128fsimple_dir)
        .files(
            scheme_sphincsshake256128fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256128frobust_dir)
        .files(
            scheme_sphincsshake256128frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256192ssimple_dir)
        .files(
            scheme_sphincsshake256192ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256192srobust_dir)
        .files(
            scheme_sphincsshake256192srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256192fsimple_dir)
        .files(
            scheme_sphincsshake256192fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256192frobust_dir)
        .files(
            scheme_sphincsshake256192frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256256ssimple_dir)
        .files(
            scheme_sphincsshake256256ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256256srobust_dir)
        .files(
            scheme_sphincsshake256256srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256256fsimple_dir)
        .files(
            scheme_sphincsshake256256fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincsshake256256frobust_dir)
        .files(
            scheme_sphincsshake256256frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256128ssimple_dir)
        .files(
            scheme_sphincssha256128ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256128srobust_dir)
        .files(
            scheme_sphincssha256128srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256128fsimple_dir)
        .files(
            scheme_sphincssha256128fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256128frobust_dir)
        .files(
            scheme_sphincssha256128frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256192ssimple_dir)
        .files(
            scheme_sphincssha256192ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256192srobust_dir)
        .files(
            scheme_sphincssha256192srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256192fsimple_dir)
        .files(
            scheme_sphincssha256192fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256192frobust_dir)
        .files(
            scheme_sphincssha256192frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256256ssimple_dir)
        .files(
            scheme_sphincssha256256ssimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256256srobust_dir)
        .files(
            scheme_sphincssha256256srobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256256fsimple_dir)
        .files(
            scheme_sphincssha256256fsimple_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .include(target_sphincssha256256frobust_dir)
        .files(
            scheme_sphincssha256256frobust_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        )
        .compile("libsphincsplus.a");
}
