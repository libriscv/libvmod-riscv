#!/bin/bash
set -e
#!/bin/bash
set -e
#export CC="ccache $CC"
#export CXX="ccache $CXX"
cmake_extra=""
do_32bit="ON"
do_64bit="OFF"
build_type="Release"
varnish_plus="OFF"

usage() {
	echo "Usage: $0 [-v] [--enterprise]"
	echo "  -v            verbose build"
	echo "  --enterprise  build for Varnish Enterprise"
	exit 1
}

for i in "$@"; do
	case $i in
		--32)
			do_32bit="ON"
			do_64bit="OFF"
			shift
			;;
		--64)
			do_32bit="OFF"
			do_64bit="ON"
			shift
			;;
		--enterprise)
            varnish_plus="ON"
            shift
            ;;
		--jit)
			cmake_extra="$cmake_extra -DRISCV_LIBTCC=ON"
			shift
			;;
		--no-jit)
			cmake_extra="$cmake_extra -DRISCV_LIBTCC=OFF"
			shift
			;;
		--bintr)
			cmake_extra="$cmake_extra -DRISCV_BINARY_TRANSLATION=ON"
			shift
			;;
		--no-bintr)
			cmake_extra="$cmake_extra -DRISCV_BINARY_TRANSLATION=OFF"
			shift
			;;
		--C)
			cmake_extra="$cmake_extra -DRISCV_EXT_C=ON"
			shift
			;;
		--no-C)
			cmake_extra="$cmake_extra -DRISCV_EXT_C=OFF"
			shift
			;;
		--native)
			cmake_extra="$cmake_extra -DNATIVE=ON"
			shift
			;;
		--no-native)
			cmake_extra="$cmake_extra -DNATIVE=OFF"
			shift
			;;
		--sanitize)
			build_type="Debug"
			cmake_extra="$cmake_extra -DSANITIZE=ON"
			shift
			;;
		--no-sanitize)
			build_type="Release"
			cmake_extra="$cmake_extra -DSANITIZE=OFF"
			shift
			;;
		--debug)
			build_type="Debug"
			cmake_extra="$cmake_extra -DSANITIZE=OFF"
			shift
			;;
		--release)
			build_type="Release"
			cmake_extra="$cmake_extra -DSANITIZE=OFF"
			shift
			;;
		-v)
			export VERBOSE=1
			shift
			;;
		-*|--*)
			echo "Unknown option $i"
			exit 1
			;;
		*)
		;;
	esac
done

# If ext/json is missing, update submodules
if [ ! -f ext/json/CMakeLists.txt ]; then
	echo "Updating git submodules"
	git submodule update --init --recursive
fi

mkdir -p .build
pushd .build
cmake .. -DCMAKE_BUILD_TYPE=$build_type -DVARNISH_PLUS=$varnish_plus -DRISCV_32I=$do_32bit -DRISCV_64I=$do_64bit $cmake_extra
cmake --build . -j6
popd

VPATH="/usr/lib/varnish/vmods/"
VEPATH="/usr/lib/varnish-plus/vmods/"
if [ "$varnish_plus" == "ON" ]; then
	VPATH=$VEPATH
fi

echo "Installing vmod into $VPATH"
sudo cp .build/libvmod_*.so $VPATH
