#!/bin/bash
# Build and test the VMOD against open-source Varnish Cache in a container,
# without touching the local (Enterprise) build. Extra arguments go to ctest.
#   VARNISH_VERSION=9.1 tests/container/run.sh -R js_
set -e
cd "$(dirname "$0")/../.."
VERSION=${VARNISH_VERSION:-9.1}
IMAGE=libvmod-riscv-vcache:$VERSION
STAGE=${STAGE:-$PWD/.build-vcache-$VERSION}

if [ ! -x program/riscv64-linux-musl/js ]; then
	echo "Missing RISC-V programs, run program/build.sh first" >&2
	exit 1
fi

docker build -q --build-arg VARNISH_VERSION=$VERSION -t $IMAGE tests/container >/dev/null

mkdir -p $STAGE/src
{ git ls-files -z --recurse-submodules; git ls-files -z --others --exclude-standard; } |
	rsync -a --from0 --files-from=- ./ $STAGE/src/
rsync -a program/riscv64-linux-musl/basic program/riscv64-linux-musl/js \
	$STAGE/src/program/riscv64-linux-musl/

docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp --tmpfs /tmp:exec \
	-v $STAGE:$STAGE -w $STAGE/src $IMAGE bash -c '
	set -e
	varnishd -V 2>&1 | head -1
	CC=clang CXX=clang++ cmake -S. -B../build -G Ninja \
		-DCMAKE_BUILD_TYPE=Release -DVARNISH_PLUS=OFF \
		-DPython3_EXECUTABLE=$(which python3) >/dev/null
	cmake --build ../build -j$(nproc)
	ctest --test-dir ../build --output-on-failure -j$(nproc) "$@"
' bash "$@"
