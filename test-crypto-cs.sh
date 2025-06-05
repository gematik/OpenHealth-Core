#!/bin/bash
set -e

./build-all.sh

cd crypto-openssl-ffi-cs-tests
dotnet test