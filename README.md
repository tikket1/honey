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

Status: **v1 pipeline complete.** All three example probes compile to eBPF bytecode the
kernel verifier accepts, the loader prints live events, and the stage 4 type checker
turns every verifier rule into an error at your source line. `examples/bad/` holds one
program per rule, each rejected with a fix hint.

## The idea in one screen

Writing eBPF in C means the kernel verifier tells you, after compiling, that
"R0 invalid mem access 'map_value_or_null'" at instruction 213. honey says this
instead, before any code is generated:

```
$ honeyc check examples/bad/unchecked_map.hny
examples/bad/unchecked_map.hny:12:13: error: cannot dereference `Option<&u64>`: the lookup may have found nothing
        let n = *prev + 1;
                ^
    help: check it first: `if let Some(v) = map.get(key) { ... *v ... }`
```

The verifier's rules, as honey enforces them: loops have constant bounds, map
lookups are `Option<&V>` and must be matched, checked pointers cannot leave
their `if`, string reads carry their bound in the type, the 512-byte stack is
budgeted at compile time, and integer widths never convert silently.

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
  src/typeck.rs      stage 4, the verifier-aware type checker
  src/codegen.rs     stage 3, AST → BPF bytecode
  src/main.rs        honeyc <file> | --tokens | --asm | build -o <out>
  tests/lexer.rs     stage 1 acceptance tests (50)
  tests/parser.rs    stage 2 acceptance tests (44)
  tests/codegen.rs   stage 3 acceptance tests (20)
  tests/typeck.rs    stage 4 acceptance tests (28)
linux/               the Linux side (build + run against a real kernel)
  loader.c           loads bytecode, attaches to a tracepoint, reads events
  honey-linux        run a command in the Docker Linux environment
  run.sh             build the loader, then load + run a compiled program
docs/LANGUAGE.md     language reference (§3 is normative for stage 1)
docs/STAGE-1.md      what to build, in what order, and the Rust you need
examples/*.hny       programs that compile and run
examples/bad/*.hny   programs the checker must reject (first line = expected error)
```

## Build & test

```bash
cargo test                                  # 158 tests
cargo run -- check examples/exec.hny       # type-check: verifier rules at your source line
cargo run -- examples/exec.hny             # parse and pretty-print
cargo run -- --asm examples/exec.hny       # show the emitted BPF assembly
cargo run -- build examples/exec.hny -o build/exec   # write bytecode + manifest

# run one against a real kernel (needs Docker Desktop):
cargo run -- build examples/sensitive_open.hny -o build/sensitive
linux/honey-linux ./linux/run.sh build/sensitive.bin build/sensitive.json
#   -> flags every open of /etc/shadow or /etc/sudoers, with the caller
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

All four stages are in place. What comes next is breadth (kprobes, LSM hooks,
more builtins, string equality, sampling) on the same skeleton.

## Prior art

ply (direct-to-bytecode without LLVM), bpftrace, Aya, KernelScript
(arXiv 2607.23900), BeePL (arXiv 2507.09883), "Kernel Extension DSLs Should
Be Verifier-Safe!" (ACM 2026).
