# Bindings to quantum-safe cryptographic libraries

This repository contains bindings to C implementations of cryptographic algorithms part of the [NIST competition][nist].
These bindings are generated based on the [PQClean][pqclean] project, which aims to collect 'clean' implementations of cryptographic algorithms.

## How this project works.

The `pqcrypto-templates` folder contains the master copies of the Rust files.
The binding libraries are generated from the PQClean meta files and PQClean specified API.
The file `implementations.yaml` controls the version numbers and included variants of each scheme.

## Documentation

See the [documentation of the master project on docs.rs][docsrs].

[nist]: https://nist.gov/pqcrypto
[pqc]: https://github.com/pqclean/pqclean/
[docsrs]: https://docs.rs/pqcrypto/
