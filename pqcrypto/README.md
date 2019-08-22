# Post-Quantum cryptographic algorithms

This project contains Post-Quantum cryptographic algorithms that participate in
the [NIST PQC standardization effort][nistpqc]. It is currently a collection of
wrappers around C implementations from the [PQClean][pqclean] project.

This super-crate contains the following cryptographic algorithms:

## Key-Encapsulation Mechanisms

* [``pqcrypto-kyber``](https://crates.io/crates/pqcrypto-kyber)
* [``pqcrypto-frodo``](https://crates.io/crates/pqcrypto-frodo)
* [``pqcrypto-ntru``](https://crates.io/crates/pqcrypto-ntru)
* [``pqcrypto-saber``](https://crates.io/crates/pqcrypto-saber)
* [``pqcrypto-ledacryptkem``](https://crates.io/crates/pqcrypto-ledacryptkem)

## Signature Schemes
* [``pqcrypto-mqdss``](https://crates.io/crates/pqcrypto-mqdss)
* [``pqcrypto-dilithium``](https://crates.io/crates/pqcrypto-dilithium)
* [``pqcrypto-falcon``](https://crates.io/crates/pqcrypto-falcon)
* [``pqcrypto-sphincsplus``](https://crates.io/crates/pqcrypto-sphincsplus)

## License

The wrappers and wrapper generation scripts in this project are covered by the
MIT or Apache 2.0 licenses, at your choice.

The implementations we link to are not, however. Please see the [PQClean][pqclean]
project for the appropriate licenses.


[pqclean]: https://github.com/PQClean/PQClean/
[nistpqc]: https://nist.gov/pqc/