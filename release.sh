#!/bin/sh

CARGO=~/git/cargo/target/debug/cargo

publish() {
    pushd $1
    ${CARGO} publish
    popd
}


publish pqcrypto-traits
publish pqcrypto-kyber
publish pqcrypto-frodo
publish pqcrypto-ntru
publish pqcrypto-sphincsplus

echo "Waiting a little bit for the packages to settle on crates.io"

sleep 30
publish pqcrypto
