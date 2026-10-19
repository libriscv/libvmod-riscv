#!/usr/bin/env bash
# Replays every artifact and prints one line per distinct crash site.
cd "$(dirname "$0")"
[ $# -eq 0 ] && set -- artifacts/*
for f in "$@"; do
	sig=$(timeout 20 ./build/fuzz_api "$f" 2>&1 | grep -v "^>>>" | grep -m1 -E "runtime error|ERROR: AddressSanitizer|varnishd would panic|wrong digest|what\(\)|ERROR: LeakSanitizer|out-of-memory" | sed -E 's/0x[0-9a-f]+//g; s/==[0-9]+==//; s/ (on address|at pc).*//')
	site=$(timeout 20 ./build/fuzz_api "$f" 2>&1 | grep -m1 -E "#[0-9]+ .* in (rvs::|riscv::Machine|riscv::Memory|vclv_|VRE_|http_|WS_)" | sed -E 's/.* in //; s/\(.*\) / /')
	echo "${sig:-no-crash} | ${site} | $f"
done | sort -t'|' -k1,2 -u
