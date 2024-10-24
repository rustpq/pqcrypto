#!/bin/sh

CARGO="cargo +nightly"

publish() {
    pushd $1
    ${CARGO} publish
    popd
}


publish pqcrypto-traits
publish pqcrypto-internals
sleep 10
echo "Waiting a little bit for the pqcrypto-traits package to settle on crates.io"
publish pqcrypto-mlkem
publish pqcrypto-hqc
publish pqcrypto-sphincsplus
publish pqcrypto-mldsa
publish pqcrypto-falcon
publish pqcrypto-classicmceliece

echo "Waiting a little bit for the packages to settle on crates.io"

sleep 30
publish pqcrypto
