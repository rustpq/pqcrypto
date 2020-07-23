# ledacryptkem

    This (implementation of an) cryptographic algorithm is insecure.
    This crate will only compile if you enable the "cryptographically-insecure" feature.

    Only use this crate and algorithm for research and educational purposes.

This crate contains bindings to the C implementations of the following schemes,
from [PQClean][pqclean].

This project packages Post-Quantum cryptographic algorithms that participate in
the [NIST PQC standardization effort][nistpqc]. It is currently a collection of
wrappers around C implementations from the [PQClean][pqclean] project.

# Included implementations from PQClean

Below is a list of the included schemes and the corresponding implementations
sourced from [PQClean][pqclean]. The "default" implementation is used in the
Rust-friendly interface, alternative implementations are exposed as ``ffi``
methods only.

 * ``ledakemlt12``
    * ``leaktime`` (default)
 * ``ledakemlt32``
    * ``leaktime`` (default)
 * ``ledakemlt52``
    * ``leaktime`` (default)

# Notes
This version of LEDA is insecure

https://eprint.iacr.org/2020/455

This implementation is not constant-time!
This means that it is not secure.

This crate may remove the ``leaktime`` implementation at any point.


## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.

[pqclean]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/