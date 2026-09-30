# VCL compiler

The VCL-to-RISC-V compiler behind `.vcl` tenants, ported from Carapace's
`carapace-vcl` and `carapace-vcl-rt`. The top-level README describes what a
tenant's VCL can do. This file describes how the pieces fit together.

| Path | What it is |
|---|---|
| `compiler/` | The compiler: preprocessor → parser → type checker → IR → RV64 codegen → ELF. Plain Rust with no dependencies but the runtime blob, and nothing in it opens a file. |
| `runtime/` | Allocation-free routines the generated code calls (cookie, URL and header lists, time and duration parsing, …), and `runtime/runtime.elf`, their pre-linked image that the compiler copies into every policy. |
| `vclc/` | The compiler built as a RISC-V guest program. It exports `vclc_compile` and makes one host call, to read an `include`. |
| `vclc.elf` | That guest, embedded in the VMOD by `src/vcl/vclc_blob.c`. |

The host side lives in `src/vcl/`:

| File | What it does |
|---|---|
| `compiler.cpp` | Runs `vclc.elf` in a fresh machine per compile, answers its includes (confined to the policy's directory), and decodes the answer under hard caps. |
| `vcl_program.cpp` | Loads a compiled policy: compiles its regex literals (`.carapace.regex`), seeds its request globals (`.carapace.globals`) into the master VM, maps its hooks to the VMOD callbacks, and stages a folded `vcl_synth`. |
| `vcl_syscalls.cpp` | The policy ABI the generated code calls, at syscalls 540..=560 (`abi.hpp`). |
| `vcl_varnish.c` | Everything that touches Varnish's own objects, in C against `cache/cache.h`. |

## The ABI

A compiled policy calls the host with Carapace's scripting ABI, shifted from
490..=510 to 540..=560 so that it sits between the VMOD's own API (500..=539)
and the native heap helpers (580..). `define_syscalls!` in
`compiler/src/ir.rs` and `src/vcl/abi.hpp` are the two halves; change both
together.

Differences from Carapace, all on the host side:

- Header edits go straight to Varnish's header maps, instead of being
  recorded and replayed after the phase.
- Carapace has no `vcl_synth`, so the compiler folds it into the hook that
  returns `synth(...)`. Its `resp` writes and `synthetic()` are staged and
  applied when `riscv.run()` is called from `vcl_synth`.
- Regular expressions are Varnish's (PCRE). The compiler still validates
  patterns against its own, stricter rules.
- `static var` is refused, and declared and dynamic statistics are gone.
  Each request runs in a fresh fork, so there is nothing to accumulate into.

## Rebuilding the blobs

Both blobs are committed, so building the VMOD needs no Rust or RISC-V
toolchain. Rebuild them after changing the compiler or the runtime:

```sh
make -C vcl/runtime/guest blob   # after changing vcl/runtime/src
make -C vcl/vclc blob            # after changing vcl/compiler or vcl/runtime
```

Both builds are pinned to Rust 1.91.0 and are reproducible, so an unchanged
source gives an unchanged blob. They need the `riscv64gc-unknown-none-elf` and
`riscv64gc-unknown-linux-gnu` targets and `riscv64-linux-gnu-gcc-14`.

The compiler's own tests run natively:

```sh
cd vcl/compiler && cargo test
```
