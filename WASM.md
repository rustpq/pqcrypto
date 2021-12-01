Support for WebAssembly
=======================

# Summary

Due to the need for a standard library in the build these quantum routines it is not
possible to compile them as pure no-std WASM however by using wasi and its standard
library it becomes possible.

# Steps

Download the wasm32-wasi sysroot build from https://github.com/WebAssembly/wasi-sdk
and set the environment variable to point to it

```sh
cd ..
wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sysroot-12.0.tar.gz
tar -xvzf wasi-sysroot-12.0.tar.gz
rm wasi-sysroot-12.0.tar.gz

sudo tee /etc/profile.d/wasi.sh <<EOF
export WASI_SDK_DIR="$(pwd)/wasi-sysroot"
EOF
source /etc/profile.d/wasi.sh
````

Note: While the source command brings the WASI export variables into your current
terminal any new terminals will miss this until you log out and back in.

You can now compile the library for linking with WebAssembly using the following
command or via cargo dependencies with the same specifics.

```sh
cd pqcrypto
cargo build --no-default-features --target wasm32-wasi --features avx2,serialization
```
