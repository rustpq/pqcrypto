extern crate cc;
extern crate glob;

use std::path::Path;

fn main() {
    let target_sphincsharaka128ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-128s-simple/clean");
    let scheme_sphincsharaka128ssimple_clean_files = glob::glob(
        target_sphincsharaka128ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka128srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-128s-robust/clean");
    let scheme_sphincsharaka128srobust_clean_files = glob::glob(
        target_sphincsharaka128srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka128fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-128f-simple/clean");
    let scheme_sphincsharaka128fsimple_clean_files = glob::glob(
        target_sphincsharaka128fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka128frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-128f-robust/clean");
    let scheme_sphincsharaka128frobust_clean_files = glob::glob(
        target_sphincsharaka128frobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka192ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-192s-simple/clean");
    let scheme_sphincsharaka192ssimple_clean_files = glob::glob(
        target_sphincsharaka192ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka192srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-192s-robust/clean");
    let scheme_sphincsharaka192srobust_clean_files = glob::glob(
        target_sphincsharaka192srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka192fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-192f-simple/clean");
    let scheme_sphincsharaka192fsimple_clean_files = glob::glob(
        target_sphincsharaka192fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka192frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-192f-robust/clean");
    let scheme_sphincsharaka192frobust_clean_files = glob::glob(
        target_sphincsharaka192frobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka256ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-256s-simple/clean");
    let scheme_sphincsharaka256ssimple_clean_files = glob::glob(
        target_sphincsharaka256ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka256srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-256s-robust/clean");
    let scheme_sphincsharaka256srobust_clean_files = glob::glob(
        target_sphincsharaka256srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka256fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-256f-simple/clean");
    let scheme_sphincsharaka256fsimple_clean_files = glob::glob(
        target_sphincsharaka256fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsharaka256frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-haraka-256f-robust/clean");
    let scheme_sphincsharaka256frobust_clean_files = glob::glob(
        target_sphincsharaka256frobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256128ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-128s-simple/clean");
    let scheme_sphincsshake256128ssimple_clean_files = glob::glob(
        target_sphincsshake256128ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256128srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-128s-robust/clean");
    let scheme_sphincsshake256128srobust_clean_files = glob::glob(
        target_sphincsshake256128srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256128fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-128f-simple/clean");
    let scheme_sphincsshake256128fsimple_clean_files = glob::glob(
        target_sphincsshake256128fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256128frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-128f-robust/clean");
    let scheme_sphincsshake256128frobust_clean_files = glob::glob(
        target_sphincsshake256128frobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256192ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-192s-simple/clean");
    let scheme_sphincsshake256192ssimple_clean_files = glob::glob(
        target_sphincsshake256192ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256192srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-192s-robust/clean");
    let scheme_sphincsshake256192srobust_clean_files = glob::glob(
        target_sphincsshake256192srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256192fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-192f-simple/clean");
    let scheme_sphincsshake256192fsimple_clean_files = glob::glob(
        target_sphincsshake256192fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256192frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-192f-robust/clean");
    let scheme_sphincsshake256192frobust_clean_files = glob::glob(
        target_sphincsshake256192frobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256256ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-256s-simple/clean");
    let scheme_sphincsshake256256ssimple_clean_files = glob::glob(
        target_sphincsshake256256ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256256srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-256s-robust/clean");
    let scheme_sphincsshake256256srobust_clean_files = glob::glob(
        target_sphincsshake256256srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256256fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-256f-simple/clean");
    let scheme_sphincsshake256256fsimple_clean_files = glob::glob(
        target_sphincsshake256256fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincsshake256256frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-shake256-256f-robust/clean");
    let scheme_sphincsshake256256frobust_clean_files = glob::glob(
        target_sphincsshake256256frobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256128ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-128s-simple/clean");
    let scheme_sphincssha256128ssimple_clean_files = glob::glob(
        target_sphincssha256128ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256128srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-128s-robust/clean");
    let scheme_sphincssha256128srobust_clean_files = glob::glob(
        target_sphincssha256128srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256128fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-128f-simple/clean");
    let scheme_sphincssha256128fsimple_clean_files = glob::glob(
        target_sphincssha256128fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256128frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-128f-robust/clean");
    let scheme_sphincssha256128frobust_clean_files = glob::glob(
        target_sphincssha256128frobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256192ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-192s-simple/clean");
    let scheme_sphincssha256192ssimple_clean_files = glob::glob(
        target_sphincssha256192ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256192srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-192s-robust/clean");
    let scheme_sphincssha256192srobust_clean_files = glob::glob(
        target_sphincssha256192srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256192fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-192f-simple/clean");
    let scheme_sphincssha256192fsimple_clean_files = glob::glob(
        target_sphincssha256192fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256192frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-192f-robust/clean");
    let scheme_sphincssha256192frobust_clean_files = glob::glob(
        target_sphincssha256192frobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256256ssimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-256s-simple/clean");
    let scheme_sphincssha256256ssimple_clean_files = glob::glob(
        target_sphincssha256256ssimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256256srobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-256s-robust/clean");
    let scheme_sphincssha256256srobust_clean_files = glob::glob(
        target_sphincssha256256srobust_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256256fsimple_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-256f-simple/clean");
    let scheme_sphincssha256256fsimple_clean_files = glob::glob(
        target_sphincssha256256fsimple_clean_dir
            .join("*.c")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let target_sphincssha256256frobust_clean_dir =
        Path::new("pqclean/crypto_sign/sphincs-sha256-256f-robust/clean");
    let scheme_sphincssha256256frobust_clean_files = glob::glob(
        target_sphincssha256256frobust_clean_dir
            .join("*.c")
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

    let common_files = vec![
        common_dir.join("fips202.c"),
        common_dir.join("aes.c"),
        common_dir.join("sha2.c"),
        common_dir.join("randombytes.c"),
    ];

    builder.files(common_files.into_iter());
    builder
        .include(target_sphincsharaka128ssimple_clean_dir)
        .files(
            scheme_sphincsharaka128ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka128srobust_clean_dir)
        .files(
            scheme_sphincsharaka128srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka128fsimple_clean_dir)
        .files(
            scheme_sphincsharaka128fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka128frobust_clean_dir)
        .files(
            scheme_sphincsharaka128frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka192ssimple_clean_dir)
        .files(
            scheme_sphincsharaka192ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka192srobust_clean_dir)
        .files(
            scheme_sphincsharaka192srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka192fsimple_clean_dir)
        .files(
            scheme_sphincsharaka192fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka192frobust_clean_dir)
        .files(
            scheme_sphincsharaka192frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka256ssimple_clean_dir)
        .files(
            scheme_sphincsharaka256ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka256srobust_clean_dir)
        .files(
            scheme_sphincsharaka256srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka256fsimple_clean_dir)
        .files(
            scheme_sphincsharaka256fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsharaka256frobust_clean_dir)
        .files(
            scheme_sphincsharaka256frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256128ssimple_clean_dir)
        .files(
            scheme_sphincsshake256128ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256128srobust_clean_dir)
        .files(
            scheme_sphincsshake256128srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256128fsimple_clean_dir)
        .files(
            scheme_sphincsshake256128fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256128frobust_clean_dir)
        .files(
            scheme_sphincsshake256128frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256192ssimple_clean_dir)
        .files(
            scheme_sphincsshake256192ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256192srobust_clean_dir)
        .files(
            scheme_sphincsshake256192srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256192fsimple_clean_dir)
        .files(
            scheme_sphincsshake256192fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256192frobust_clean_dir)
        .files(
            scheme_sphincsshake256192frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256256ssimple_clean_dir)
        .files(
            scheme_sphincsshake256256ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256256srobust_clean_dir)
        .files(
            scheme_sphincsshake256256srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256256fsimple_clean_dir)
        .files(
            scheme_sphincsshake256256fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincsshake256256frobust_clean_dir)
        .files(
            scheme_sphincsshake256256frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256128ssimple_clean_dir)
        .files(
            scheme_sphincssha256128ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256128srobust_clean_dir)
        .files(
            scheme_sphincssha256128srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256128fsimple_clean_dir)
        .files(
            scheme_sphincssha256128fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256128frobust_clean_dir)
        .files(
            scheme_sphincssha256128frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256192ssimple_clean_dir)
        .files(
            scheme_sphincssha256192ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256192srobust_clean_dir)
        .files(
            scheme_sphincssha256192srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256192fsimple_clean_dir)
        .files(
            scheme_sphincssha256192fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256192frobust_clean_dir)
        .files(
            scheme_sphincssha256192frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256256ssimple_clean_dir)
        .files(
            scheme_sphincssha256256ssimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256256srobust_clean_dir)
        .files(
            scheme_sphincssha256256srobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256256fsimple_clean_dir)
        .files(
            scheme_sphincssha256256fsimple_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder
        .include(target_sphincssha256256frobust_clean_dir)
        .files(
            scheme_sphincssha256256frobust_clean_files
                .into_iter()
                .map(|p| p.unwrap().to_string_lossy().into_owned()),
        );
    builder.compile("libsphincsplus.a");
}
