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

Two of the three example programs compile and run in-kernel:

| Program                      | Status                                                  |
|------------------------------|---------------------------------------------------------|
| `examples/exec.hny`          | runs: emit an event with builtin fields                 |
| `examples/exec_burst.hny`    | runs: `const`, `hash` map get/insert, `if let`, arithmetic, threshold compare |
| `examples/sensitive_open.hny`| parses only: needs `for`, `read_user_str`, string compare (stage 3c) |

Supported: `const` integer literals; `map` (`hash<K, V>`, `array<V>`) with
`.get`, `.insert`, `.delete`; `let`, assignment, `if`/`else`,
`if let Some(x) = map.get(k)`, `return`, `emit`; integer/bool literals, names,
nullary builtins (`pid tgid tid uid gid ktime`), `comm()` as an emit field,
`*ptr`, unsigned arithmetic/bitwise/comparison, `&&`/`||`/`!`.

Not yet (clear "not yet" errors, never unverifiable bytecode): `for`, string
values and `read_user_str`, `as` casts, signed comparisons, writing through a
map pointer, `field.access`, indexing.

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
- Stack use is tracked and the compiler refuses anything over 512 bytes.

## The verifier is your test oracle

The kernel refuses to load a program it can't prove safe, and its rejection
message is the ground truth for whether codegen is correct. When you extend
codegen, the loop is: emit, load, read the verifier's complaint, fix. Stage 4
moves those complaints to compile time.
