# Changelog

## 2019-07-24

* Ditch ``pqcrypto-internals``
* Update PQClean
* Package Falcon

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
