#!/bin/bash
set -e

./build-all.sh

cd asn1-ffi-cs-tests
dotnet test