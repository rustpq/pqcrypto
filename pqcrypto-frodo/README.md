# frodo

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

 * ``frodokem640shake``
    * ``opt`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``frodokem640aes``
    * ``opt`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``frodokem976aes``
    * ``opt`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``frodokem976shake``
    * ``opt`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``frodokem1344aes``
    * ``opt`` (default)
    * ``clean`` (included as ``ffi`` only)
 * ``frodokem1344shake``
    * ``opt`` (default)
    * ``clean`` (included as ``ffi`` only)

# Notes
If you use it via the FFI interface: The ``clean`` implementation of Frodo
needs a lot of stack space, specify env variable `RUST_MIN_STACK` to make
sure it has enough stack space in threads.

This is not relevant for the 'normal' api methods.


## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.

[pqc]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/