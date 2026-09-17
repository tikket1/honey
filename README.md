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

Status: **v1 complete: tracepoints, kprobes (with kernel struct-field reads),
uprobes and USDT markers, LSM enforcement, XDP packet filtering, sampling,
string equality, multi-probe programs, and JSON output with typed fields
(`ipv4` prints as a dotted quad).** Every example
compiles to eBPF bytecode the kernel verifier accepts and the loader prints live
events (text, or `--json` for a log pipeline). The stage 4 type checker turns every verifier rule into an error
at your source line; `examples/bad/` holds one program per rule, each rejected with a
fix hint.

The examples show the range: `examples/icmp_drop.hny` (XDP) drops ICMP on an
interface, and `examples/getenv_trace.hny` (uprobe) reads the env-var name a
process looks up straight out of libc. `examples/shadow_open_ok.hny` (kprobe + kretprobe)
reports only the opens of `/etc/shadow` that *succeeded*. `examples/lsm_block_uid.hny`
(LSM) does not just watch — it *blocks*. `examples/file_open_path.hny` walks kernel
structs from a kprobe argument (`path -> dentry -> d_name -> name`) to print the
filename of every open, with offsets resolved from BTF so the probe survives a
kernel upgrade.

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
  src/btf.rs         reads the kernel's BTF (type info) for struct-field offsets
  src/layout.rs      event record byte layout
  src/typeck.rs      stage 4, the verifier-aware type checker
  src/codegen.rs     stage 3, AST → BPF bytecode
  src/main.rs        honeyc <file> | --tokens | --asm | build -o <out>
  tests/lexer.rs     stage 1 acceptance tests (50)
  tests/parser.rs    stage 2 acceptance tests (44)
  tests/codegen.rs   stage 3 acceptance tests (42)
  tests/typeck.rs    stage 4 acceptance tests (53)
  tests/kernel_fields.rs  struct-field read tests (10, synthetic BTF)
linux/               the Linux side (build + run against a real kernel)
  loader.c           loads bytecode, attaches (tracepoint/kprobe/uprobe/usdt/lsm/xdp), reads events
  usdt_demo.c        a program with a USDT marker + semaphore, for the usdt example
  honey-linux        run a command in the Docker Linux environment
  run.sh             build the loader, then load + run a compiled program
docs/LANGUAGE.md     language reference (§3 is normative for stage 1)
docs/STAGE-1.md      what to build, in what order, and the Rust you need
examples/*.hny       programs that compile and run (tracepoint, kprobe + kretprobe)
examples/bad/*.hny   programs the checker must reject (first line = expected error)
```

## Build & test

```bash
cargo test                                  # 218 tests
cargo run -- check examples/exec.hny       # type-check: verifier rules at your source line
cargo run -- examples/exec.hny             # parse and pretty-print
cargo run -- --asm examples/exec.hny       # show the emitted BPF assembly
cargo run -- build examples/exec.hny -o build/exec   # write bytecode + manifest

# run one against a real kernel (needs Docker Desktop):
cargo run -- build examples/lsm_block_uid.hny -o build/lsm
linux/honey-linux ./linux/run.sh --json build/lsm.bin build/lsm.json
#   -> {"event":"Blocked","uid":4242,"pid":23944,"comm":"setpriv"}
#      and the quarantined uid's open is denied with EPERM
# reading kernel struct fields needs the kernel's BTF:
linux/export-btf                                            # build/vmlinux.btf
cargo run -- build examples/file_open_path.hny -o build/fop --btf build/vmlinux.btf
linux/honey-linux ./linux/run.sh --json build/fop.bin build/fop.json
#   -> {"event":"OpenPath","pid":36239,"uid":0,"comm":"cat","file":"hostname"}
# packets: drop ICMP on loopback and watch ping fail
cargo run -- build examples/icmp_drop.hny -o build/icmp
linux/honey-linux ./linux/run.sh --json build/icmp.bin build/icmp.json
#   -> {"event":"Dropped","src":"127.0.0.1","dst":"127.0.0.1","ttl":64}

# userspace: trace env-var lookups via a uprobe on libc getenv
cargo run -- build examples/getenv_trace.hny -o build/getenv
linux/honey-linux ./linux/run.sh --json build/getenv.bin build/getenv.json
#   -> {"event":"Getenv","pid":70055,"comm":"date","name":"TZ"}
# compiling for an x86_64 box: add --arch x86_64 (kprobe register layout)
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

All four stages are in place, plus kprobes/kretprobes and multi-probe programs.
The v1 feature list is done. Natural next steps: USDT argument access, IPv6
and MAC field types, and a `honey run` one-shot command that builds and loads.

## Prior art

ply (direct-to-bytecode without LLVM), bpftrace, Aya, KernelScript
(arXiv 2607.23900), BeePL (arXiv 2507.09883), "Kernel Extension DSLs Should
Be Verifier-Safe!" (ACM 2026).
