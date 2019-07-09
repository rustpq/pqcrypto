#!/bin/sh

CARGO=~/git/cargo/target/debug/cargo

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
publish pqcrypto-sphincsplus
publish pqcrypto-mqdss

echo "Waiting a little bit for the packages to settle on crates.io"

sleep 30
publish pqcrypto
