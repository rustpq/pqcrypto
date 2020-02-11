# classicmceliece

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

 * ``mceliece348864``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece348864f``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece460896``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece460896f``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece6688128``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece6688128f``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece6960119``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece6960119f``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece8192128``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``mceliece8192128f``
    * ``avx`` (if supported)
    * ``vec`` (default)
    * ``clean`` (included as ``ffi`` only)


## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.

[pqclean]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/