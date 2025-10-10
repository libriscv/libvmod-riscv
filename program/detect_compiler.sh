# System-provided GCC variants
export GCC_TRIPLE="riscv32-unknown-elf"
# Check for ccache
if command -v ccache >/dev/null 2>&1; then
	export CC="ccache $GCC_TRIPLE-gcc"
	export CXX="ccache $GCC_TRIPLE-g++"
else
	export CC="$GCC_TRIPLE-gcc"
	export CXX="$GCC_TRIPLE-g++"
fi
