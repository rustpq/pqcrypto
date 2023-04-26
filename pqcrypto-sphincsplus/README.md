# sphincsplus


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

* ``sphincs-haraka-128f-robust``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-128f-simple``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-128s-robust``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-128s-simple``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-192f-robust``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-192f-simple``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-192s-robust``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-192s-simple``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-256f-robust``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-256f-simple``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-256s-robust``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-haraka-256s-simple``
  * ``clean``
  * ``aesni`` (if supported)
* ``sphincs-shake-128f-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-128f-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-128s-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-128s-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-192f-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-192f-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-192s-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-192s-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-256f-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-256f-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-256s-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-shake-256s-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-128f-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-128f-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-128s-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-128s-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-192f-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-192f-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-192s-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-192s-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-256f-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-256f-simple``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-256s-robust``
  * ``clean``
  * ``avx2`` (if supported)
* ``sphincs-sha2-256s-simple``
  * ``clean``
  * ``avx2`` (if supported)


## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.

[pqclean]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/