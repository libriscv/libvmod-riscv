#!/bin/bash
set -e
cd "$(dirname "$0")"

export GCC_TRIPLE="riscv64-linux-musl"
ZIG="${ZIG:-zig}"
if ! command -v "$ZIG" >/dev/null 2>&1; then
	echo "Error: zig not found (set ZIG=/path/to/zig)" >&2
	exit 1
fi
export CC="$ZIG cc -target $GCC_TRIPLE"
export CXX="$ZIG c++ -target $GCC_TRIPLE"

mkdir -p $GCC_TRIPLE
pushd $GCC_TRIPLE
cmake ../cpp -DGCC_TRIPLE=$GCC_TRIPLE -DCMAKE_TOOLCHAIN_FILE=micro/toolchain.cmake
make -j$(nproc)
popd
