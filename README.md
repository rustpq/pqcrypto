# Bindings to quantum-safe cryptographic libraries

[![dependency status](https://deps.rs/repo/github/rustpq/pqcrypto/status.svg)](https://deps.rs/repo/github/rustpq/pqcrypto)

This repository contains bindings to C implementations of cryptographic algorithms part of the [NIST competition][nist].
These bindings are generated based on the [PQClean][pqclean] project, which aims to collect 'clean' implementations of cryptographic algorithms.

## A note on upstream PQClean

The C implementations vendored by these crates are sourced from [PQClean][pqclean].
PQClean has announced that it will be [archived as read-only in July 2026][pqclean],
and the implications for this project are being tracked in [#97][issue97].

Because PQClean is the upstream source for the vendored C, fixes that previously
flowed upstream — for example portability and build-system issues such as
[#98][issue98] — may need to be tracked in this repository going forward. If you
hit a build or portability problem, please open an issue here so it can be
considered for the next release rather than assuming it will be resolved upstream.

## How to generate the bindings

The `pqcrypto-templates` folder contains the master copies of the Rust files.
The binding libraries are generated from the PQClean meta files and PQClean specified API.
The file `implementations.yaml` controls the version numbers and included variants of each scheme.
The generation of the different pq-crates is done by the `generate-implementation.py` script.

## Documentation

See the [documentation of the master project on docs.rs][docsrs].

[nist]: https://nist.gov/pqcrypto
[pqclean]: https://github.com/PQClean/PQClean/
[docsrs]: https://docs.rs/pqcrypto/
[issue97]: https://github.com/rustpq/pqcrypto/issues/97
[issue98]: https://github.com/rustpq/pqcrypto/issues/98
