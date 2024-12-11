# Changelog

## 2024-12-11
* `pqcrypto-hqc` was updated to addresss a security flaw in decapsulation.

## 2024-10-24
* `pqcrypto-kyber` and `pqcrypto-dilithium` are retired and replaced by `pqcrypto-mlkem` and `pqcrypto-mldsa`, respectively.
* `pqcrypto-falcon` now separates Falcon into the "compressed" mode and the "padded" variants. The "compressed" variant likely produces shorter signatures than the max size.

## 2024-01-25

* Update Kyber `clean` implementation to avoid potential Kyber side-channel vulnerabilities.
  Note that the `aarch64` implementation is still vulnerable, but it is waiting for other updates.
  This library is for experimental purposes, so security vulnerabilties are addressed on a best-effort basis.

## 2023-10-16

* Update Kyber to draft FIPS standard
    * Remove 90s variants
* Update Dilithium to draft FIPS standard
    * Remove 90s variants
* Update McEliece implementation
    * Remove Vec variants
* Bring SPHINCS+ to closer to FIPS variants by removing -robust and Haraka variants
* Small fix in Falcon
* Add Falcon NEON implementation
* Update Rust edition to 2021

## 2023-04-26

* Update Rust dependencies
* Update SPHINCS+ implementation
* Update Falcon implementation

## 2022-11-16

* Add support for Dilithium*AES instances

## 2022-10-21

* Remove schemes eliminated from the NIST competition as they are no longer
  tracked by PQClean
  * Frodo
  * NTRU
  * NTRU Prime
  * Rainbow
  * SABER
* Update HQC implementation from PQClean
  * Fixes aliasing violation

## 2022-04-13

* Update schemes
  * NTRU small fixes
  * Dilithium fixes
  * McEliece small fix
  * SPHINCS+ small fixes
  * SABER NEON implementation
  * Kyber neon
* Many build system fixes

## 2021-12-07

* Add AArch64 compilation option for supported schemes
  * NTT operations can now compute with NEON support

## 2021-12-01

* Add WebAssembly (WASM) support

## 2021-11-24

* Add a general implementation list for each scheme in implementations.yaml which is used by build.rs.j2
* Each scheme now has a list of supported implementation variants
* Refactor build.rs.js2 to use macro calls
* Update the other template files to adapt to this change
* Slight modifications to README.md
* Update PQClean
  * Larger-size NTRU parametersets

## 2021-10-26

* Make `pqcrypto-internals` cross-compilable

## 2021-10-18

* Fix small issue in randombytes implementation: should return 0

## 2021-09-20

* `no_std` support thanks to @rozbb (PR#25)
* Extract randombytes from PQClean-provided APIs (avoids symbol conflict) (PR #24)
* Update PQClean:
  * NTRUPrime new parametersets
  * Small Falcon fixes
  * Small NTRU fix

## 2021-07-28

* Falcon updates: remove inline functions from headerfiles
* Enable Falcon AVX2
* NTRU Prime updates
* Move common files into `pqcrypto-internals` and out of individual libs

## 2021-06-28

* Refactor the wrapper methods in scheme.rs.js2 file to macro calls

## 2021-06-10

* Add optional `serde` support
* HQC bugfixes
  * Issues still remain, disabled AVX2 implementations of HQC for now.
* McEliece fixes
* Round 3 parameters for SPHINCS+

## 2021-02-26

* Update CRYSTALS-Kyber schemes to Round 3
* Update FrodoKEM schemes to Round 3
* Update NTRU schemes to Round 3
* Add NTRU Prime schemes
* Update Saber schemes to Round 3
  * Add AVX2 implementation
* Update HQC schemes to Round 3
  * Add polynomial carry-less multiplication flag (pclmul) to compile flags
  * Disable AVX2 implementation of HQC-RMRS-256 as there is a bug in "compute_syndromes()" in reed_solomon.c
* Update CRYSTALS-Dilithium schemes to Round 3
* Update Falcon schemes
* Update Rainbow schemes to Round 3
  * Disable doc-tests for RainbowV because of stack overflow
  * Add stack size notification for Rainbow schemes
* Sort the scheme variants alphabetically in implementations.yaml

## 2020-08-27

* :alert: **Removed non-round-3 implementations**
* Update NTRU
* Small update in Saber code

## 2020-06-22

* Update FrodoKEM implementations to fix timing side channel
* Update MQDSS

## 2020-05-25

* Make paths more resilient to windows

## 2020-04-03

* Add HQC

## 2020-03-27

* Update implementations to PQClean latest versions
  * Kyber
  * Dilithium
  * Falcon

## 2020-02-11

* Add Classic McEliece
* Support MacOS for Dilithium AVX2
* Add ephemeral versions (CPA secure) of Threebears
* Put buffers in tests on the heap

## 2019-12-18

* Include SPHINCS+ AVX2 and AESNI implementations
* Refactor build system to separately build all the implementations.
* Somewhere since the last version we also included Dilithium AVX2 implementations.

## 2019-11-20

* Update Rainbow implementations to mitigate [``memcopy`` bug][pqclean/250] ([#5][#5])
* Don't try to compile Kyber-AVX2 on MacOS

[#5]: https://github.com/rustpq/pqcrypto/issues/5
[pqclean/250]: https://github.com/pqclean/pqclean/pull/250

## 2019-11-04

* Add Kyber-90s (with AVX2)
* Add NEWHOPE
* Add qTESLA
* Add Threebears
* Release fixed version of Rainbow
* Don't try to build AVX2 versions of code on Windows

## 2019-09-24

* Update FALCON implementations, as they were insecure.
  See [IACR ePrint report 2019/893](https://eprint.iacr.org/2019/893).

* Support Kyber AVX2 implementations (this may break Windows support).

## 2019-08-22

* Update PQClean upstream
* Support upcoming AVX2 implementations from PQClean

## 2019-08-07

* Update PQClean upstream
* Update FALCON from PQClean
* Update SPHINCS+ from PQClean
* Package LEDAcryptKEM
  * **Warning:** The LEDAcryptKEM implementations currently packaged are known to have timing side-channel vulnerabilities.
* Package Rainbow
  * The ``clean`` implementations are currently known to have undefined behaviour.
      See [pqclean/issues/220](https://github.com/PQClean/PQClean/issues/220)
* Hide a internal enum variable from ``pqcrypto_traits::sign::VerificationError``

## 2019-07-24

* Ditch ``pqcrypto-internals``
* Update PQClean
* Package Falcon
* Make nicer docs and READMEs

## 2019-07-22

* Update `rand` crate to `0.7.0`

## 2019-07-18

* Update PQClean implementations
  * SPHINCS+ is now thread-safe.
  * Frodo now uses ``opt`` implementation by default.
* Allow for multiple implementations in the ``ffi`` interface.

## 2019-07-09

* Make ``encapsulate`` and ``decapsulate`` take references.
* Add Dilithium
* Add SABER

## 2019-07-08

* Remove ``pqcrypto-internals``

## 2019-05-22

* Added ``pqcrypto_traits::{Error,Result}`` to ``from_bytes`` signature.
* Added ``pqcrypto::prelude`` to allow importing all traits in one easy go.
* Removed all uses of ``mem::uninitialized()``

## 2019-05-21

* Added MQDSS
