#!/usr/bin/env bash

set -euo pipefail

# Config
OPENSSL_VERSION=8fabfd81094d1d9f8890df4bee083aa6f77d769d
OPENSSL_TARGET=darwin64-arm64-cc
INSTALL_DIR="$(pwd)/openssl-${OPENSSL_TARGET}"
SRC_DIR="$(pwd)/openssl-src"

# Clean old dirs
rm -rf "$SRC_DIR" "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Clone OpenSSL
git clone https://github.com/openssl/openssl.git "$SRC_DIR"
cd "$SRC_DIR"
git checkout "$OPENSSL_VERSION"

# Configure
./Configure "$OPENSSL_TARGET" \
    --prefix="$INSTALL_DIR" \
    no-asm no-async no-egd no-ktls no-module no-posix-io \
    no-secure-memory no-shared no-sock no-stdio no-thread-pool \
    no-threads no-ui-console no-docs

# Build & install
make -j"$(sysctl -n hw.ncpu)"
make install