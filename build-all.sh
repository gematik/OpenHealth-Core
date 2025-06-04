#!/bin/bash
set -e

cargo clean
cargo build --release

FFI_LIB=$(find . -name "libasn1_ffi.dylib" | head -n 1)

if [ -n "$FFI_LIB" ]; then
  mkdir -p asn1-ffi-cs-tests/bin/Debug/net9.0
  cp "$FFI_LIB" asn1-ffi-cs-tests/bin/Debug/net9.0/
fi