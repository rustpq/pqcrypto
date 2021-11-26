# classicmceliece


This crate contains bindings to the C implementations of the following schemes,
from [PQClean][pqclean].

This project packages Post-Quantum cryptographic algorithms that participate in
the [NIST PQC standardization effort][nistpqc]. It is currently a collection of
wrappers around C implementations from the [PQClean][pqclean] project.

## Serialization

If you want `serde` support, enable the `serialization` feature.

## Included implementations from PQClean

Below is a list of the included schemes and the corresponding implementations
sourced from [PQClean][pqclean]. The "default" implementation is used in the
Rust-friendly interface, alternative implementations are exposed as ``ffi``
methods only.

* ``mceliece348864``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece348864f``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece460896``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece460896f``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece6688128``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece6688128f``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece6960119``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece6960119f``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece8192128``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)
* ``mceliece8192128f``
  * ``vec``
  * ``clean``
  * ``avx`` (if supported)

## Notes

This implementation requires a lot of stack space.
You need to specify ``RUST_MIN_STACK=800000000``, probably.


## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.

[pqclean]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/