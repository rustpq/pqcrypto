#!/bin/sh

CARGO="cargo +nightly"

publish() {
    pushd $1
    ${CARGO} publish
    popd
}


publish pqcrypto-traits
sleep 10
echo "Waiting a little bit for the pqcrypto-traits package to settle on crates.io"
publish pqcrypto-kyber
publish pqcrypto-frodo
publish pqcrypto-ntru
publish pqcrypto-ntruprime
publish pqcrypto-hqc
publish pqcrypto-sphincsplus
publish pqcrypto-saber
publish pqcrypto-dilithium
publish pqcrypto-falcon
publish pqcrypto-rainbow
publish pqcrypto-classicmceliece

echo "Waiting a little bit for the packages to settle on crates.io"

sleep 30
publish pqcrypto
