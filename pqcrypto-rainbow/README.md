# rainbow

    This (implementation of an) cryptographic algorithm is insecure.
    This crate will only compile if you enable the "cryptographically-insecure" feature.

    Only use this crate and algorithm for research and educational purposes.

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

* ``rainbowI-circumzenithal``
  * ``clean``
* ``rainbowI-classic``
  * ``clean``
* ``rainbowI-compressed``
  * ``clean``
* ``rainbowIII-circumzenithal``
  * ``clean``
* ``rainbowIII-classic``
  * ``clean``
* ``rainbowIII-compressed``
  * ``clean``
* ``rainbowV-circumzenithal``
  * ``clean``
* ``rainbowV-classic``
  * ``clean``
* ``rainbowV-compressed``
  * ``clean``

## Notes

This implementation requires a lot of stack space.
You need to specify ``RUST_MIN_STACK=800000000``, probably.

Rainbow does no longer get the claimed security, see
https://eprint.iacr.org/2022/214.pdf


## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.

[pqclean]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/