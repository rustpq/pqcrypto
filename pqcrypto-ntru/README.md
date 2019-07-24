# ntru

This crate contains bindings to the C implementations of the following schemes,
from [PQClean][pqc].

This project packages Post-Quantum cryptographic algorithms that participate in
the [NIST PQC standardization effort][nistpqc]. It is currently a collection of
wrappers around C implementations from the [PQClean][pqclean] project.

# Included implementations from PQClean

Below is a list of the included schemes and the corresponding implementations
sourced from [PQClean][pqclean]. The "default" implementation is used in the
Rust-friendly interface, alternative implementations are exposed as ``ffi``
methods only.

 * ``ntruhps2048509``
    * ``clean`` (default)
 * ``ntruhps2048677``
    * ``clean`` (default)
 * ``ntruhps4096821``
    * ``clean`` (default)
 * ``ntruhrss701``
    * ``clean`` (default)


## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.

[pqc]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/