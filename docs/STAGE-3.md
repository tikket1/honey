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

## What codegen supports today

Every example program compiles and runs in-kernel, each verified in the
commit that added it:

| Program                        | What it shows                                                                 |
|--------------------------------|-------------------------------------------------------------------------------|
| `examples/exec.hny`            | tracepoint; emit an event with builtin fields                                 |
| `examples/exec_burst.hny`      | `const`, `hash` map get/insert, `if let`, arithmetic, threshold compare       |
| `examples/sensitive_open.hny`  | `arg(n)`, `read_user_str` into `str<N>`, `starts_with`, `byte_at`, unrolled `for`, bit tests |
| `examples/shadow_open_ok.hny`  | `kprobe` + `kretprobe` on one function, map keyed by `tid()`, `retval()` signed compare, `i64` |
| `examples/lsm_block_uid.hny`   | `lsm("file_open")` enforcement: `deny()` blocks a quarantined uid (EPERM)     |
| `examples/file_open_path.hny`  | kernel struct walk `path -> dentry -> d_name -> name` via BTF, CO-RE-style relocation |
| `examples/exec_shell.hny`      | `path == "/bin/sh"` exact string equality on the execve filename              |
| `examples/exec_sampled.hny`    | `sample(100)`: 2 events from 200 execs                                        |
| `examples/getenv_trace.hny`    | `uprobe(libc:getenv)` reading the env-var name, a user string argument        |
| `examples/usdt_tick.hny`       | `usdt(usdt_demo:honey:tick)` with `arg(0)`/`arg(1)` from the note, semaphore |
| `examples/icmp_drop.hny`       | `xdp("lo")` drops ICMP; `ipv4` fields; `src == "127.0.0.1"`                   |
| `examples/ipv6_ping.hny`       | `ipv6`/`mac` fields, `src != "::1"`                                           |
| `examples/xdp_structs.hny`     | `ptr<ethhdr>`/`ptr<iphdr>` views, `ip.saddr` through the anonymous union, `in_subnet` |
| `examples/xdp_structs6.hny`    | `ptr<ipv6hdr>` view, `in6_addr` as `ipv6`, IPv6 `in_subnet`                   |
| `examples/xdp_tcp4.hny`        | `ip.ihl` bitfield + `pkt.view(14 + ihl*4)` runtime-offset view of `tcphdr`   |
| `examples/xdp_tcp6.hny`        | `pkt.ipv6_l4` extension-header walk + `pkt.l4()` (extension branches verifier-checked; test traffic has none) |
| `examples/xdp_synopts.hny`     | `tcp.opt(kind)` through `if let`: MSS 65495, wscale 7, SACK ok, tsval from a loopback SYN |
| `examples/xdp_pong.hny`        | packet writes (`eth.h_dest = eth.h_source`, `ip.ttl = 7`), `ip.fix_csum()`, `csum_update`, `tx()`: ping answered from XDP with `ttl=7`; without `fix_csum` the stack drops every reply |

Supported: `const`; `map` (`hash<K, V>`, `array<V>`) with `.get`, `.insert`,
`.delete`; `let`, assignment, `if`/`else`, `if let Some(x) = map.get(k)`,
unrolled `for`, `return`, `emit`; integer/bool literals; builtins per probe
kind (`pid tgid tid uid gid ktime comm arg retval deny allow drop pass
sample in_subnet read_user_str read_kernel_str`); `*ptr`; unsigned and
`i64` arithmetic/bitwise/comparison; `&&`/`||`/`!`; `str<N>` with
`starts_with`, `byte_at`, `==`/`!=`; `ipv4`/`ipv6`/`mac` with `==`/`!=`;
kernel struct reads via `ptr<S>`; packet views, bitfields, runtime views,
the IPv6 walk; packet writes through views, `fix_csum`, `csum_update`,
`tcp.opt`, `tx`.

Not supported (clear errors, never unverifiable bytecode): `as` casts,
signed widths other than `i64`, `return <value>`, writing through map
pointers, dynamic loop bounds, functions, more than one live runtime view,
writing bitfields or raw packet offsets (writes go through a view's fields).

### Probe kinds and multiple probes

Each `probe` compiles to its own BPF program; a `.bin` holds them
concatenated and the manifest records each one's offset, type, and attach
target. Tracepoints attach through their tracefs id; kprobes and kretprobes
through the kprobe perf PMU (function name in `config1`, the retprobe flag
in `config`). `arg(n)` in a kprobe reads `struct pt_regs`, whose layout is
per architecture: pass `--arch x86_64` when compiling for an x86 box (the
default is aarch64, the dev environment). Every record starts with an
8-byte header carrying the event id so one ring buffer serves every probe.

### Userspace functions (uprobes)

A `uprobe`/`uretprobe` is `BPF_PROG_TYPE_KPROBE` attached through the uprobe
perf PMU. The loader resolves `path:symbol` to a file offset by reading the
binary's ELF symbol table (libelf), matching the base name of a versioned
symbol and converting the symbol's virtual address to a file offset via the
containing `PT_LOAD` segment. `arg(n)` reads `pt_regs` like a kprobe, and
because the arguments are user pointers, `read_user_str` works on them.

### USDT markers

A `usdt` probe is a uprobe at a marker address the loader reads from the
binary's `.note.stapsdt` notes (libelf `gelf_getnote`): each note carries the
marker's address, the link-time address of `.stapsdt.base` (if that section
moved, the marker moved by the same amount), an optional semaphore address,
and `provider\0name\0args\0`. Addresses are converted to file offsets via
`PT_LOAD`. When there is a semaphore, its file offset goes into the perf
attr's `config` bits 32..63 (`ref_ctr_offset`) and the kernel increments the
counter in every process running the binary while the probe is attached —
`linux/usdt_demo.c` prints "probe enabled" exactly then.

**USDT arguments** are the one place codegen cannot know the answer at
compile time: the note's argument string (`-4@x19 8@x24` on aarch64,
`-4@%eax 8@-8(%rbp)` on x86_64) is per binary and per build. honey follows
libbpf's design. Codegen emits a *generic* read for `arg(n)`: look up this
program's 96-byte spec in the hidden `__honey_usdt` array map (keyed by
program index), and per the arg's kind either take a constant, read a
register out of `pt_regs` (`bpf_probe_read_kernel` of `ctx + reg_off`),
or read a register and dereference it in user memory
(`bpf_probe_read_user`), then shift left and right to extract the sized,
correctly signed value. The loader parses the note's operands per
architecture into that spec and writes it to the map before attaching.

The loader prints `ipv4` fields as dotted quads; honey byte-swapped the value
on read, so the high byte is the first octet.

### Sampling

`sample(N)` compiles to a lookup-increment-modulo against a hidden
`__honey_sample` array map that honey adds automatically, one u64 counter per
call site. It fires on every Nth call. No map declaration, no state to manage.

### Packets (XDP)

An `xdp` probe is `BPF_PROG_TYPE_XDP`, attached to an interface with
`bpf_xdp_attach` in generic (skb) mode so it works on any device, loopback
and veth included. XDP programs outlive the loader's file descriptors, so the
loader detaches them on SIGINT/SIGTERM. The prologue loads `data`/`data_end`
from the `xdp_md` context into R7/R8 (callee-saved, so helper calls keep
them) and emits one bounds check for the largest offset the body reads; each
`pkt.uN(off)` is then a plain load the verifier has already proven safe, with
a `bswap` for 16/32-bit values. The default return is `XDP_PASS`.

**Packet struct views.** `let ip: ptr<iphdr> = pkt.at(14)` is a compile-time
binding: `Ty::PktPtr(btf type id, offset)`, nothing emitted. `ip.saddr` looks
the member up in BTF by type id — descending through anonymous struct/union
members, which is how modern kernels wrap `saddr`/`daddr` — and emits a plain
load from `[R7 + 14 + 12]`. Carrying ids rather than names is what lets a
chain pass through anonymous types: `icmp.un.echo.sequence` names `un`, a
member whose type has no name, and `echo` inside it. If the member's typedef chain names a `__be*` type the
load is followed by a `bswap`, so network-order fields arrive host-order.
Byte arrays of 6/16 and `struct in6_addr` are blobs copied with the usual
chunked copy; embedded structs become deeper views; bitfields and pointers
are rejected by the checker. The pre-pass adds `offset + sizeof(struct)` to
the entry bound.

**Bitfields.** A bitfield member (BTF records its bit offset and width) is
read by loading the narrowest 1/2/4/8-byte container that covers the bits,
then `rsh` by the bit offset within the container and `and` with the width
mask. BTF numbers bits little-endian, which is exactly how a little-endian
load places them in a register, so no swap is involved. The same shape is
used for kernel-struct bitfields via `bpf_probe_read_kernel`.

**Dynamic views.** `pkt.view(expr)` evaluates the offset, masks it to 12
bits so the verifier has a bound, builds `R9 = data + off`, and checks
`R9 + sizeof(S) <= data_end` once; the checked pointer stays in `R9`
(callee-saved, reserved from the allocator while the probe uses dynamic
views) and field reads are `[R9 + member]`. The verifier tracks the range
on that register, which is why the pointer is kept rather than recomputed.

**IPv6 extension walk.** `pkt.ipv6_l4(off)` reads `nexthdr` from the IPv6
header (covered by the entry bound), sets `R9 = data + off + 40`, and
unrolls four hops: if the current protocol is an extension kind
(0/43/44/60/51) check that 2 bytes are readable at `R9`, read the next
protocol and the length byte, compute the header size (fragment 8,
AH `(len+2)*4`, otherwise `(len+1)*8` — a packet byte scaled by ≤ 8, so
bounded) and advance `R9`. It ends with the transport protocol in `R0` and
`R9` at the transport header, which `pkt.l4()` then bounds-checks for the
struct it binds.

**Subnet matching.** `in_subnet(u32, "a.b.c.d/n")` is `(addr & mask) ==
(net & mask)` with both immediates folded at compile time. For `ipv6` it is
one masked compare per non-zero 8-byte chunk of the mask (so `/10` is a
single compare and `/128` is two), the literal loaded in the byte order the
CPU reads it.

`ipv6` and `mac` values are byte blobs, not registers: `pkt.ipv6(off)` in a
`let` allocates a 16-byte stack buffer and copies the packet bytes into it;
in an `emit` it copies packet → record directly. Copies go in 8/4/2/1-byte
chunks (unaligned packet loads are fine on the targets that run eBPF). Their
widths count toward the entry bounds check. The loader prints them with
`inet_ntop` and `%02x:` formatting.

### Reading kernel struct fields (CO-RE-lite)

A kprobe/LSM argument typed `ptr<S>` can be walked with `.field`. honey reads
the kernel's BTF (`--btf build/vmlinux.btf`, exported by `linux/export-btf`)
at compile time to know each field's offset and whether it is a scalar (read
it), an embedded struct (keep the offset pending), or a pointer (a bounded
`bpf_probe_read_kernel`). A pointer value is `Ty::KPtr { id, root, path, off }`:
the BTF type it currently designates, the named struct it really points at,
the dotted member path from that struct, and the path's compile-time offset.
Embedded structs (named or anonymous) only extend the path; every actual
read emits one `add reg, <offset>` recorded in the manifest as a
`(struct, "a.b.c")` relocation. Before loading, the loader re-walks each path
segment by segment against the *running* kernel's BTF — through anonymous
members, like C — and rewrites the immediate. A probe
compiled against one kernel's layout therefore reads the right bytes on
another — verified by corrupting the baked offsets and watching the loader
restore them from BTF.

### How values move (read `codegen.rs` with this in mind)

- Every expression evaluates into `R0`.
- **Register allocation.** Scalar locals and binary-operator temporaries
  live in the callee-saved registers `R6..R9` that the probe isn't already
  reserving — `R6` when it emits (record pointer), `R7`/`R8` in XDP (packet
  bounds), `R9` in USDT (arg spec) — and fall back to 8-byte stack slots
  when the pool is empty. Callee-saved registers survive helper calls, so a
  parked value needs no spill. Buffers (`str<N>`, `ipv6`, `mac`) always live
  on the stack. Registers are handed back when a scope ends, LIFO like the
  stack. Honest note: BPF has no memory-operand ALU forms, so this does not
  shrink the instruction count — a `mov r9, r0` costs the same as a
  `stx64 [r10-16], r0`. It removes the stack traffic (exec_burst now has
  zero scalar reloads) and cuts stack use, and it lets the verifier track a
  map pointer's null check directly on the register that holds it.
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
