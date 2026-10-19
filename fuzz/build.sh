#!/usr/bin/env bash
# Builds the libFuzzer harness for the scripting API into fuzz/build.
set -e
cd "$(dirname "$0")"
for v in {22..14}; do
	if command -v "clang++-$v" &> /dev/null; then
		CLANG_VERSION="-$v"
		break
	fi
done
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
	-DCMAKE_C_COMPILER="clang${CLANG_VERSION}" \
	-DCMAKE_CXX_COMPILER="clang++${CLANG_VERSION}"
cmake --build build -j"$(nproc)"
