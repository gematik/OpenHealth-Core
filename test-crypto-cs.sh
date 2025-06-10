#!/bin/bash
set -e

./build-all.sh

cd crypto-ffi-cs-tests
dotnet test