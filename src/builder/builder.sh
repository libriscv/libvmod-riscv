#!/usr/bin/env bash
set -e

PROGPATH=$1
FILE=$2
FINALFILE=$3

PROGRAMS="$PROGPATH/program"
TOOLCHAIN="$PROGRAMS/micro/toolchain.cmake"

CODETMPDIR=${FINALFILE}.d
mkdir -p $CODETMPDIR
trap 'rm -rf -- "$CODETMPDIR"' EXIT

pushd $CODETMPDIR > /dev/null
ln -s $FILE program.cpp

cat <<\EOT >CMakeLists.txt
cmake_minimum_required(VERSION 3.12)
project(programs CXX)

include(${PROGRAMS}/micro/micro.cmake)

add_micro_binary(program program.cpp)
EOT

source $PROGRAMS/detect_compiler.sh

cmake . -DGCC_TRIPLE=$GCC_TRIPLE -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN -DPROGRAMS=$PROGRAMS 2>&1
make -j16 2>&1
popd > /dev/null

mv $CODETMPDIR/program $FINALFILE
#echo "Moved $CODETMPDIR/program to $FINALFILE"
