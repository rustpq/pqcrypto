# Bindings to quantum-safe cryptographic libraries

> [!WARNING]
> **This project is unmaintained.**
>
> `pqcrypto` and its `pqcrypto-*` crates are no longer actively maintained: they
> will not receive updates for new PQClean releases, new algorithms, bug fixes or
> security fixes. The published crates will remain available on crates.io so that
> existing builds keep working, but you should not use them in new projects and
> should plan to migrate away from them.
>
> See [issue #97][issue97] for the announcement and discussion, including
> suggested alternatives.
>
> **We recommend [RustCrypto][rustcrypto] instead.** It provides actively
> maintained, pure-Rust implementations of the standardized post-quantum
> algorithms, including [`ml-kem`][ml-kem] (ML-KEM/Kyber),
> [`ml-dsa`][ml-dsa] (ML-DSA/Dilithium) and [`slh-dsa`][slh-dsa]
> (SLH-DSA/SPHINCS+).
>
> Other actively maintained options:
>
> * [`aws-lc-rs`][aws-lc-rs], which exposes the post-quantum algorithms in AWS-LC.
> * [`liboqs-rust`][liboqs-rust], bindings to [liboqs][liboqs], if you need broad
>   coverage of NIST PQC candidates similar to what this project offered.

[![dependency status](https://deps.rs/repo/github/rustpq/pqcrypto/status.svg)](https://deps.rs/repo/github/rustpq/pqcrypto)

This repository contains bindings to C implementations of cryptographic algorithms part of the [NIST competition][nist].
These bindings are generated based on the [PQClean][pqclean] project, which aims to collect 'clean' implementations of cryptographic algorithms.

## How to generate the bindings

The `pqcrypto-templates` folder contains the master copies of the Rust files.
The binding libraries are generated from the PQClean meta files and PQClean specified API.
The file `implementations.yaml` controls the version numbers and included variants of each scheme.
The generation of the different pq-crates is done by the `generate-implementation.py` script.

## Documentation

See the [documentation of the master project on docs.rs][docsrs].

[issue97]: https://github.com/rustpq/pqcrypto/issues/97
[rustcrypto]: https://github.com/RustCrypto
[ml-kem]: https://crates.io/crates/ml-kem
[ml-dsa]: https://crates.io/crates/ml-dsa
[slh-dsa]: https://crates.io/crates/slh-dsa
[aws-lc-rs]: https://crates.io/crates/aws-lc-rs
[liboqs-rust]: https://github.com/open-quantum-safe/liboqs-rust
[liboqs]: https://github.com/open-quantum-safe/liboqs
[nist]: https://nist.gov/pqcrypto
[pqclean]: https://github.com/pqclean/pqclean/
[docsrs]: https://docs.rs/pqcrypto/
