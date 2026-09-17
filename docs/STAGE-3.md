# Stage 3 — bytecode and the loader

Stage 3 is where honey stops being a pure-Mac exercise and starts running
inside a real Linux kernel. It has two halves:

- **Mac side (Rust):** turn the AST into eBPF bytecode. Modules `bpf.rs`
  (the instruction encoder + disassembler) and `codegen.rs` (AST → program),
  with `layout.rs` computing event record layouts. Fully testable on macOS.
- **Linux side (C):** `linux/loader.c` loads the bytecode into the kernel,
  attaches it to a tracepoint, and prints the events. Needs a Linux kernel.

## The Linux environment

You don't need a full VM. Docker Desktop already runs a Linux kernel (6.12,
with BPF + BTF), and a privileged container on it can load BPF programs. The
helper wraps that:

```bash
linux/honey-linux                      # interactive shell in the environment
linux/honey-linux make -C linux        # build the loader
```

The image carries only userspace tooling (clang, gcc, libbpf); the kernel is
Docker's own. First run builds the image.

## The end-to-end loop

```bash
# 1. Compile a probe to bytecode + a manifest (on macOS):
cargo run -- build examples/exec.hny -o build/exec
#    -> build/exec.bin  (raw eBPF instructions)
#    -> build/exec.json (tracepoint, ring-buffer size, event layout)

# 2. Load and run it (in the Linux environment):
linux/honey-linux ./linux/run.sh build/exec.bin build/exec.json
#    prints: pid=... uid=... comm=... for every execve, system-wide
```

Inspect the bytecode without a kernel:

```bash
cargo run -- --asm examples/exec.hny   # disassemble what codegen produced
```

## What the loader does (the kernel ABI, step by step)

1. **Create the ring-buffer map** (`bpf_map_create`). This is the channel the
   program uses to push event records to userspace.
2. **Relocate the map reference.** honeyc emits `ld64 r1, map_fd(0)` — a
   placeholder. The loader rewrites that immediate to the real map fd. This is
   the one link between the statically-compiled program and the runtime map.
3. **Load the program** (`bpf_prog_load`). The kernel verifier runs here. If
   honey emitted anything unsafe, this is where it is rejected — which is
   exactly the failure mode stage 4's type system exists to prevent.
4. **Attach to the tracepoint.** Read the tracepoint's numeric id from
   tracefs, `perf_event_open` it, and `ioctl(PERF_EVENT_IOC_SET_BPF)`. That
   binds the program to the tracepoint for the whole system.
5. **Poll the ring buffer** and decode each record using the field offsets in
   the manifest.

## What codegen supports today (and what's next)

All example programs compile and run in-kernel:

| Program                      | Status                                                  |
|------------------------------|---------------------------------------------------------|
| `examples/exec.hny`          | runs: emit an event with builtin fields                 |
| `examples/exec_burst.hny`    | runs: `const`, `hash` map get/insert, `if let`, arithmetic, threshold compare |
| `examples/sensitive_open.hny`| runs: `arg(n)`, `read_user_str` into `str<N>`, `starts_with`, `byte_at`, bounded (unrolled) `for`, bit tests |
| `examples/shadow_open_ok.hny`| runs: `kprobe` + `kretprobe` on the same function, shared map keyed by `tid()`, `retval()` with a signed compare, `i64` field |

Supported: `const` integer literals; `map` (`hash<K, V>`, `array<V>`) with
`.get`, `.insert`, `.delete`; `let`, assignment, `if`/`else`,
`if let Some(x) = map.get(k)`, `return`, `emit`; integer/bool literals, names,
nullary builtins (`pid tgid tid uid gid ktime`), `comm()` as an emit field,
`*ptr`, unsigned arithmetic/bitwise/comparison, `&&`/`||`/`!`.

Bounded `for` loops are **fully unrolled**: both ends must be compile-time
constants, so the verifier sees straight-line code with no back-edge. The loop
variable is a constant inside the body. Strings are fixed `str<N>` stack
buffers; `read_user_str` reads into one, `starts_with`/`byte_at` read out of
one, and an `emit` copies one into the record.

Not yet (clear "not yet" errors, never unverifiable bytecode): `as` casts,
signed comparisons, `return <value>`, writing through a map pointer, dynamic
loop bounds, `field.access` beyond builtins, indexing.

### Probe kinds and multiple probes

Each `probe` compiles to its own BPF program; a `.bin` holds them
concatenated and the manifest records each one's offset, type, and attach
target. Tracepoints attach through their tracefs id; kprobes and kretprobes
through the kprobe perf PMU (function name in `config1`, the retprobe flag
in `config`). `arg(n)` in a kprobe reads `struct pt_regs`, whose layout is
per architecture: pass `--arch x86_64` when compiling for an x86 box (the
default is aarch64, the dev environment). Every record starts with an
8-byte header carrying the event id so one ring buffer serves every probe.

### Packets (XDP)

An `xdp` probe is `BPF_PROG_TYPE_XDP`, attached to an interface with
`bpf_xdp_attach` in generic (skb) mode so it works on any device, loopback
and veth included. XDP programs outlive the loader's file descriptors, so the
loader detaches them on SIGINT/SIGTERM. The prologue loads `data`/`data_end`
from the `xdp_md` context into R7/R8 (callee-saved, so helper calls keep
them) and emits one bounds check for the largest offset the body reads; each
`pkt.uN(off)` is then a plain load the verifier has already proven safe, with
a `bswap` for 16/32-bit values. The default return is `XDP_PASS`.

### Reading kernel struct fields (CO-RE-lite)

A kprobe/LSM argument typed `ptr<S>` can be walked with `.field`. honey reads
the kernel's BTF (`--btf build/vmlinux.btf`, exported by `linux/export-btf`)
at compile time to know each field's offset and whether it is a scalar (read
it), an embedded struct (add its offset), or a pointer (a bounded
`bpf_probe_read_kernel`). Each hop is emitted as an `add reg, <offset>` and
recorded in the manifest as a `(struct, field)` relocation. Before loading,
the loader re-resolves every relocation against the *running* kernel's BTF
(`btf__find_by_name_kind` + member walk) and rewrites the immediate. A probe
compiled against one kernel's layout therefore reads the right bytes on
another — verified by corrupting the baked offsets and watching the loader
restore them from BTF.

### How values move (read `codegen.rs` with this in mind)

- Every expression evaluates into `R0`.
- Locals are 8-byte stack slots at `[R10 - off]`, allocated per scope and
  released in LIFO order. Binary operators spill the left operand to a
  scratch slot, compute the right, reload into `R1`, and combine.
- `map.get(k)` stores the key on the stack, calls `bpf_map_lookup_elem`, and
  the result is *spilled and then null-checked*. The verifier propagates the
  null check to the spilled copy, so reloading it inside the `if let` body
  yields a pointer it will let you dereference. That is the one place codegen
  leans on a verifier subtlety, and it is exactly the rule stage 4 makes a type.
- `R6` holds the ring-buffer record during an `emit`; helper calls preserve
  it, so field expressions can call maps and builtins freely.
- The tracepoint context pointer (R1 at entry) is spilled to a stack slot in
  the prologue, so `arg(n)` can read `*(ctx + 16 + 8n)` after R1 is reused.
- Stack use is tracked and the compiler refuses anything over 512 bytes.

## The verifier is your test oracle

The kernel refuses to load a program it can't prove safe, and its rejection
message is the ground truth for whether codegen is correct. When you extend
codegen, the loop is: emit, load, read the verifier's complaint, fix. Stage 4
moves those complaints to compile time.
