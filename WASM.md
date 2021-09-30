Support for WebAssembly
=======================

# Summary

Due to the need for a standard library in the build these quantum routines it is not
possible to compile them as pure no-std WASM however by using wasi and its standard
library it becomes possible.

# Steps

Download the wasm32-wasi sysroot build from https://github.com/WebAssembly/wasi-sdk and
extract it into the parent director

```sh
cd ..
wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sysroot-12.0.tar.gz
tar -xvzf wasi-sysroot-12.0.tar.gz
rm wasi-sysroot-12.0.tar.gz
````

You can now compile the library for linking with WebAssembly using the following
command or via cargo dependencies with the same specifics.

```sh
cd pqcrypto
cargo build --no-default-features --target wasm32-wasi --features avx2,serialization
```
