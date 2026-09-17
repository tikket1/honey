# honey

A typed language for Linux eBPF security probes that compiles straight to
BPF bytecode (no LLVM), with a type system designed so that *if it
typechecks, the kernel verifier accepts it*.

```honey
event Exec { pid: u32, uid: u32, comm: str<16> }

probe tracepoint("syscalls", "sys_enter_execve") {
    emit Exec { pid: pid(), uid: uid(), comm: comm() };
}
```

Status: **stages 1-3 working end to end.** honey compiles `examples/exec.hny` to eBPF
bytecode that the kernel verifier accepts, and the loader prints live execve events.
Next: stage 3b (maps, control flow, arithmetic) and stage 4 (verifier-aware types).

## Layout

```
crates/honeyc/        the compiler (Rust, no dependencies)
  src/token.rs       token vocabulary — the lexer/parser contract
  src/lexer.rs       stage 1, done
  src/ast.rs         tree shape — the parser/later-stages contract
  src/parser.rs      stage 2, done
  src/pretty.rs      AST → source, for debugging and round-trip tests
  src/bpf.rs         eBPF instruction encoder + disassembler
  src/layout.rs      event record byte layout
  src/codegen.rs     stage 3, AST → BPF bytecode (first slice)
  src/main.rs        honeyc <file> | --tokens | --asm | build -o <out>
  tests/lexer.rs     stage 1 acceptance tests (50)
  tests/parser.rs    stage 2 acceptance tests (44)
  tests/codegen.rs   stage 3 acceptance tests (7)
linux/               the Linux side (build + run against a real kernel)
  loader.c           loads bytecode, attaches to a tracepoint, reads events
  honey-linux        run a command in the Docker Linux environment
  run.sh             build the loader, then load + run a compiled program
docs/LANGUAGE.md     language reference (§3 is normative for stage 1)
docs/STAGE-1.md      what to build, in what order, and the Rust you need
examples/*.hny      programs the compiler must eventually accept
```

## Build & test

```bash
cargo test                                  # 117 tests
cargo run -- examples/exec.hny             # parse and pretty-print
cargo run -- --asm examples/exec.hny       # show the emitted BPF assembly
cargo run -- build examples/exec.hny -o build/exec   # write bytecode + manifest

# run it against a real kernel (needs Docker Desktop):
linux/honey-linux ./linux/run.sh build/exec.bin build/exec.json
```

Stages 1–2 run entirely on macOS. Stage 3 (loading bytecode into a kernel)
needs Linux: a UTM/QEMU VM or a small cloud box with kernel ≥ 5.8 for ring
buffers.

## Roadmap

1. **Lexer** — text → tokens.
2. **Parser** — tokens → AST.
3. **Codegen + loader** — AST → BPF bytecode, hand-encoded; a C loader that
   attaches it and reads events.
4. **Verifier-aware types** — bounded loops, checked map lookups, stack
   budget, bounded reads: illegal-to-verify becomes illegal-to-typecheck.

## Prior art

ply (direct-to-bytecode without LLVM), bpftrace, Aya, KernelScript
(arXiv 2607.23900), BeePL (arXiv 2507.09883), "Kernel Extension DSLs Should
Be Verifier-Safe!" (ACM 2026).
