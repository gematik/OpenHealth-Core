#!/bin/bash
set -e

cargo clean
cargo build --release

FFI_LIB=$(find . -name "libasn1_ffi.dylib" | head -n 1)

if [ -n "$FFI_LIB" ]; then
  mkdir -p asn1-ffi-cs-tests/bin/Debug/net9.0
  cp "$FFI_LIB" asn1-ffi-cs-tests/bin/Debug/net9.0/
fi

CRYPTO_FFI_LIB=$(find . -name "libcrypto_openssl_ffi.dylib" | head -n 1)

if [ -n "$CRYPTO_FFI_LIB" ]; then
  mkdir -p crypto-openssl-ffi-cs-tests/bin/Debug/net9.0
  cp "$CRYPTO_FFI_LIB" crypto-openssl-ffi-cs-tests/bin/Debug/net9.0/
fi