# Changelog

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
      See https://github.com/PQClean/PQClean/issues/220
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
