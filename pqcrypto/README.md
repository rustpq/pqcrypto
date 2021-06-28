# Post-Quantum cryptographic algorithms

This project contains Post-Quantum cryptographic algorithms that participate in
the [NIST PQC standardization effort][nistpqc]. It is currently a collection of
wrappers around C implementations from the [PQClean][pqclean] project.

## Insecure algorithms

This crate contains optional support for insecure algorithms. They can be enabled via the
``cryptographically-insecure`` flag.

This crate also contains algorithms that have non-constant time implementations.
Always check the relevant algorithms for their security details.

## Included algorithms

This super-crate contains the following cryptographic algorithms:

## Key-Encapsulation Mechanisms

* [``pqcrypto-kyber``](https://crates.io/crates/pqcrypto-kyber)
* [``pqcrypto-frodo``](https://crates.io/crates/pqcrypto-frodo)
* [``pqcrypto-ntru``](https://crates.io/crates/pqcrypto-ntru)
* [``pqcrypto-ntruprime``](https://crates.io/crates/pqcrypto-ntruprime)
* [``pqcrypto-saber``](https://crates.io/crates/pqcrypto-saber)
* [``pqcrypto-classicmceliece``](https://crates.io/crates/pqcrypto-classicmceliece)
* [``pqcrypto-hqc``](https://crates.io/crates/pqcrypto-hqc)

## Signature Schemes

* [``pqcrypto-dilithium``](https://crates.io/crates/pqcrypto-dilithium)
* [``pqcrypto-falcon``](https://crates.io/crates/pqcrypto-falcon)
* [``pqcrypto-rainbow``](https://crates.io/crates/pqcrypto-rainbow)
* [``pqcrypto-sphincsplus``](https://crates.io/crates/pqcrypto-sphincsplus)

## Serialization

If you want `serde` support, enable the `serialization` feature.
You may also enable it for individual algorithms via `pqcrypto-{alg}/serialization`.

## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.

[pqclean]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/