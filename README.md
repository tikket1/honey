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

Eight probe kinds (tracepoint, kprobe/kretprobe, uprobe/uretprobe, USDT,
LSM, XDP), kernel struct reads with CO-RE-style relocation, packet headers
by name including bitfields, writes, checksums, TCP options, payloads and
DNS, LSM enforcement, sampling and rate limiting, string and address
matching, multi-probe programs, JSON output. ~8k lines of dependency-free Rust plus a C loader.

## Quick start

Needs Rust and Docker Desktop (its Linux kernel is where probes run).

```bash
./honey run examples/exec_shell.hny --json --then '/bin/sh -c true'
```

That compiles the probe, loads it into the kernel, runs the trigger command
in the same environment two seconds later, and prints the events:

```
{"event":"Shell","pid":33083,"uid":0,"comm":"bash","path":"/bin/sh"}
```

Without `--then` the loader keeps running and printing until Ctrl-C.

## Commands

| Task                                   | Command |
|----------------------------------------|---------|
| type-check a probe                     | `./honey check probe.hny` |
| see the BPF assembly it compiles to    | `./honey asm probe.hny` |
| compile to bytecode + manifest         | `./honey build probe.hny` → `build/<name>.{bin,json}` |
| run it in the kernel, print events     | `./honey run probe.hny [--json]` (Ctrl-C to stop) |
| run it, trigger something, stop        | `./honey run probe.hny --json --then "CMD"` |
| ...with a setup step before loading    | `./honey run probe.hny --json --prep "CMD" --then "CMD"` |
| a shell in the Linux environment       | `./honey shell` (joins a running `./honey run` session: same netns) |
| compile for an x86_64 box              | `./honey build probe.hny --arch x86_64` |
| export the kernel's BTF by hand        | `linux/export-btf` (done automatically when a probe uses `ptr<...>`) |
| load a build without recompiling       | `linux/honey-linux ./linux/run.sh --json build/x.bin build/x.json` |
| tests / lint                           | `cargo test` (273) · `cargo clippy --all-targets` |
| see a verifier rule caught at the line | `./honey check examples/bad/unchecked_map.hny` |

## Every example, as one line

Each line was run as written; the output shown is what it printed.

**Processes**

```bash
./honey run examples/exec.hny --json --then 'ls >/dev/null'
#  {"event":"Exec","pid":32435,"uid":0,"comm":"sh"}  ...every exec on the machine
./honey run examples/exec_shell.hny --json --then '/bin/sh -c true'
#  {"event":"Shell","pid":33083,"uid":0,"comm":"bash","path":"/bin/sh"}
./honey run examples/exec_burst.hny --json --then 'for i in $(seq 105); do /bin/true; done'
#  {"event":"Burst","uid":0,"count":101}  ...fires from the 101st exec by one uid
./honey run examples/exec_sampled.hny --json --then 'for i in $(seq 200); do /bin/true; done'
#  two events: sample(100) keeps 1 in 100
```

**Files**

```bash
./honey run examples/sensitive_open.hny --json --then 'cat /etc/shadow >/dev/null'
#  {"event":"SensitiveOpen","pid":33201,"uid":0,"write":false,"path":"/etc/shadow"}
./honey run examples/shadow_open_ok.hny --json --then 'cat /etc/shadow >/dev/null'
#  {"event":"ShadowOpen","pid":33337,"uid":0,"fd":4}   ...only opens that succeeded
./honey run examples/file_open_path.hny --json --then 'cat /etc/hostname >/dev/null'
#  {"event":"OpenPath","pid":269,"uid":0,"comm":"cat","file":"hostname"}   (kernel struct walk, BTF-relocated)
```

**Enforcement (LSM)**

```bash
./honey run examples/lsm_block_uid.hny --json --then 'setpriv --reuid=4242 --regid=4242 --clear-groups cat /etc/hostname'
#  {"event":"Blocked","uid":4242,"pid":33422,"comm":"setpriv"}   and cat gets EPERM
```

**Userspace**

```bash
./honey run examples/getenv_trace.hny --json --then 'date >/dev/null'
#  {"event":"Getenv","pid":33681,"comm":"date","name":"LANG"}   ...one per getenv call
./honey run examples/usdt_tick.hny --json --prep 'make -s -C linux usdt_demo' --then 'timeout 1.5 ./linux/usdt_demo >/dev/null'
#  {"event":"Tick","pid":37118,"comm":"usdt_demo","n":0,"msg":"hello"}
```

**Packets (XDP on loopback)**

```bash
./honey run examples/icmp_drop.hny --json --then 'ping -c 3 -W 1 127.0.0.1'
#  {"event":"Dropped","src":"127.0.0.1","dst":"127.0.0.1","ttl":64,"local":true}   and ping: 100% loss
./honey run examples/xdp_structs.hny --json --then 'ping -c 1 127.0.0.1'
#  {"event":"Seen","proto":1,"ttl":64,"src":"127.0.0.1","dst":"127.0.0.1","smac":"00:00:00:00:00:00","loopback":true,"private":false}
./honey run examples/ipv6_ping.hny --json --then 'ping -6 -c 1 ::1'
#  {"event":"Icmp6","smac":"00:00:00:00:00:00","dmac":"00:00:00:00:00:00","src":"::1","dst":"::1","next":58}
./honey run examples/xdp_structs6.hny --json --then 'ping -6 -c 1 ::1'
#  {"event":"Seen6","next":58,"hops":64,"src":"::1","dst":"::1","linklocal":false,"loopback":true}
./honey run examples/xdp_tcp4.hny --json --then 'nc -l 2223 >/dev/null & sleep 0.3; echo hi | nc -q1 127.0.0.1 2223'
#  {"event":"Tcp4","src":"127.0.0.1","dst":"127.0.0.1","sport":35312,"dport":2223,"ihl":5}
./honey run examples/xdp_tcp6.hny --json --then 'nc -6 -l 2224 >/dev/null & sleep 0.3; echo hi | nc -6 -q1 ::1 2224'
#  {"event":"Tcp6","src":"::1","dst":"::1","proto":6,"sport":50382,"dport":2224}
./honey run examples/xdp_synopts.hny --json --then 'nc -l 2225 >/dev/null & sleep 0.3; echo hi | nc -q1 127.0.0.1 2225'
#  {"event":"Syn","src":"127.0.0.1","sport":50406,"dport":2225,"mss":65495,"wscale":7,"sack_ok":true,"tsval":3305026068}
./honey run examples/xdp_http.hny --json --then "nc -l 2226 >/dev/null & sleep 0.3; printf 'GET /admin HTTP/1.0\r\n\r\n' | nc -q1 127.0.0.1 2226"
#  {"event":"Http","src":"127.0.0.1","sport":52134,"len":23,"line":"GET /admin HTTP/1.0\r\n\r\n"}
./honey run examples/xdp_udp_syslog.hny --json --then "printf '<38>sshd[812]: Failed password for root from 10.0.0.9' | nc -u -q1 127.0.0.1 5140"
#  {"event":"AuthFail","src":"127.0.0.1","sport":36589,"line":"<38>sshd[812]: Failed password for root from 10.0.0.9"}
./honey run examples/xdp_dns.hny --json --then "for i in 1 2 3 4 5 6 7; do printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05honey\x04test\x00\x00\x01\x00\x01' | nc -u -q0 127.0.0.1 53; done"
#  {"event":"Query","src":"127.0.0.1","id":4660,"name":"honey.test","qtype":1}  x5, then {"event":"Flood","src":"127.0.0.1"} x2
./honey run examples/xdp_pong.hny --json --then 'ping -c 3 127.0.0.1'
#  {"event":"Pong","src":"127.0.0.1","dst":"127.0.0.1","seq":1}   and ping shows ttl=7: XDP answered, not the kernel
./honey run examples/xdp_redirect.hny --json --prep 'ip link add veth0 type veth peer name veth1 && ip link set veth0 up && ip link set veth1 up' --then 'ping -c 3 -W 1 127.0.0.1'
#  {"event":"Moved","src":"127.0.0.1","dst":"127.0.0.1"}  then  {"event":"Arrived","src":"127.0.0.1","dst":"127.0.0.1","ttl":64}  on veth1
```

## The idea in one screen

Writing eBPF in C means the kernel verifier tells you, after compiling, that
"R0 invalid mem access 'map_value_or_null'" at instruction 213. honey says this
instead, before any code is generated:

```
$ ./honey check examples/bad/unchecked_map.hny
examples/bad/unchecked_map.hny:12:13: error: cannot dereference `Option<&u64>`: the lookup may have found nothing
        let n = *prev + 1;
                ^
    help: check it first: `if let Some(v) = map.get(key) { ... *v ... }`
```

The verifier's rules, as honey enforces them: loops have constant bounds, map
lookups and TCP options are `Option`s that must be matched, DNS types are
read only after the name, checked pointers
cannot leave their `if`, every packet read carries its bound, one runtime
packet view is live at a time, string reads carry their bound in the type,
the 512-byte stack is budgeted at compile time, and integer widths never
convert silently. `examples/bad/` holds one program per rule; the first
line of each is the error it gets.

## The environment

`linux/honey-linux` runs a command in a privileged Ubuntu container on Docker
Desktop's kernel (6.12, `CONFIG_BPF_LSM=y`), with the repo at `/work`. While
one session is running, further calls join the *same* container, so a
second terminal sees the probe's network namespace:

```bash
./honey run examples/xdp_http.hny --json      # terminal 1
./honey shell                                 # terminal 2: nc, ping, ip link ... as above
```

The image has `nc` (openbsd), `ping`, `iproute2`, gcc/clang, libbpf, and
`systemtap-sdt-dev` for the USDT demo. Kernel BTF is exported to
`build/vmlinux.btf` on first use of a probe with `ptr<...>`.

## Layout

```
honey                 the front end: ./honey run|check|build|asm|shell
crates/honeyc/src/    the compiler (Rust, no dependencies)
  lexer.rs parser.rs  text → tokens → AST (ast.rs; pretty.rs prints it back)
  typeck.rs           the verifier-aware type checker (stage 4)
  codegen.rs          AST → BPF bytecode; register allocator; packet model
  bpf.rs              instruction encoder + disassembler
  btf.rs              kernel BTF reader (struct layouts, bitfields, anonymous members)
  layout.rs addr.rs   event record layout; ipv4/ipv6/mac/CIDR literals
  main.rs             honeyc check | --asm | build -o, --btf, --arch
crates/honeyc/tests/  273 tests (lexer, parser, codegen, typeck, kernel_fields with a synthetic BTF)
linux/                loader.c (attach every kind, relocate, print events), Dockerfile, honey-linux, run.sh, export-btf, usdt_demo.c
docs/LANGUAGE.md      the language reference     docs/STAGE-{1,3,4}.md  design notes per stage
examples/*.hny        the programs above          examples/bad/*.hny     one rejected program per rule
```

## Prior art

ply (direct-to-bytecode without LLVM), bpftrace, Aya, KernelScript
(arXiv 2607.23900), BeePL (arXiv 2507.09883), "Kernel Extension DSLs Should
Be Verifier-Safe!" (ACM 2026).
