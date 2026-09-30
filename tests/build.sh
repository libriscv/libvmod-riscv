#!/usr/bin/env bash
CLANG_VERSION=10
for v in {22..11}
do
	if command -v "clang-$v" &> /dev/null
	then
		CLANG_VERSION=$v
		break
	fi
done
export RCC="clang-${CLANG_VERSION}"
export RLD="ld.lld-${CLANG_VERSION}"
$RCC -O0 -Wall -Wextra -I$2 -target riscv64 -march=rv64imafd -ffreestanding -nostdlib -c $1 -o $3.o
$RLD -Ttext=0x120000 $3.o -o $3
