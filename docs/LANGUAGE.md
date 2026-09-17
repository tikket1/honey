# honey — language reference (v1 draft)

honey is a small, typed language for writing Linux eBPF *detection probes*:
programs that attach to a kernel hook (a syscall tracepoint, a kprobe), look
at what is happening, and emit an event to userspace when something matters.

It compiles **straight to BPF bytecode** with no LLVM in the loop, and its type
system is designed so that a program that typechecks is a program the kernel
verifier accepts. Errors point at your source line, not at instruction 213.

This document is the working spec. Section 3 (lexical structure) is
normative for stage 1 and is what `crates/honeyc/tests/lexer.rs` enforces.
Everything after it is a draft that will firm up as each stage lands.

---

## 1. Design goals

1. **Verifier-safe by construction.** If it typechecks, it loads. No unbounded
   loops, no unchecked map pointers, no out-of-bounds stack access, no
   unbounded memory reads. Each of these is a *type* or *syntax* rule, not a
   runtime discovery.
2. **Security detection first.** v1 targets kprobe/tracepoint programs that
   emit records to a ring buffer. Enforcement (LSM) and networking (XDP) are
   explicitly out of scope for v1.
3. **No hidden runtime.** No heap, no GC, no stdlib beyond BPF helpers. What
   you write is what runs.
4. **Familiar surface.** Syntax is deliberately Rust-flavoured, because the
   compiler author is learning Rust at the same time.

## 2. A complete program

```honey
const THRESHOLD: u64 = 100;

map execs: hash<u32, u64>[1024];

event Burst {
    uid: u32,
    count: u64,
}

probe tracepoint("syscalls", "sys_enter_execve") {
    let uid = uid();
    let mut n: u64 = 0;

    if let Some(prev) = execs.get(uid) {
        n = *prev;
    }
    n = n + 1;
    execs.insert(uid, n);

    if n > THRESHOLD {
        emit Burst { uid: uid, count: n };
    }
}
```

A program is a list of *items*: `const`, `map`, `event`, and `probe`
declarations. Each `probe` becomes one BPF program with its own 512-byte
stack; probes share the maps and the event ring buffer. The loader attaches
every probe and prints the events, dispatching on an id in each record.

Probe kinds:

| Probe                                        | Hook                                       | Gives you |
|----------------------------------------------|--------------------------------------------|-----------|
| `tracepoint("syscalls", "sys_enter_openat")` | a static kernel tracepoint                 | `arg(n)`, process context |
| `kprobe("do_sys_openat2")`                   | entry of a kernel function                 | `arg(n)` as `ptr<S>` struct reads, process context |
| `kretprobe("do_sys_openat2")`                | return of a kernel function                | `retval()`, process context |
| `uprobe("/lib/libc.so.6:getenv")`            | entry of a userspace function              | `arg(n)` (user pointers: `read_user_str`), process context |
| `uretprobe("/lib/libc.so.6:getenv")`         | return of a userspace function             | `retval()`, process context |
| `usdt("/usr/bin/python3:python:function__entry")` | a static marker compiled into a binary | `arg(n)` (from the marker's note), process context |
| `lsm("file_open")`                           | a kernel access-control hook               | `arg(n)`, `deny()`, `allow()`, process context |
| `xdp("eth0")`                                | packets arriving on an interface           | `pkt`, `drop()`, `pass()` — no process context |

A tracepoint sees the *request*; to know the *result* hook the function with
a `kprobe` and a `kretprobe` and correlate them through a map keyed by
`tid()` (see `examples/shadow_open_ok.hny`). Any number of probes can share a
program; each is its own BPF program with its own stack budget and the
builtins that make sense for it — using the wrong one is a type error.

### Reading kernel structs (kprobe, LSM)

A kernel argument is usually a pointer to a struct. Give it a type and walk
it with `.`; pointers are followed with bounded kernel reads, embedded
structs are offsets, byte arrays (`task_struct.comm`) are readable strings:

```honey
probe kprobe("vfs_open") {                       // vfs_open(struct path *, struct file *)
    let p: ptr<path> = arg(0);
    let name: str<64> = read_kernel_str(p.dentry.d_name.name);
    emit Open { file: name };
}
```

Field names, offsets, widths and endianness come from the kernel's BTF,
passed at compile time (`./honey run` exports and passes it for you). Every
field access is also recorded in the manifest and re-resolved by the loader
against the running kernel's BTF before loading, so a compiled probe reads
the right bytes after a kernel upgrade (CO-RE, honey-sized). Bitfields are
read with a shift and mask; unknown structs and fields are compile errors.

### Enforcement (LSM)

An `lsm` probe runs inside the kernel's access-control path and can *block*:
`deny()` returns from the probe denying the action (the syscall fails with
EPERM), `allow()` returns allowing it, and falling off the end allows. The
hook name is a kernel LSM hook without the `bpf_lsm_` prefix, for example
`file_open`, `bprm_check_security`, `task_kill`.

### Userspace functions and markers (uprobe, USDT)

A `uprobe` names `path:symbol`; the symbol's offset in the file is resolved
at load time, so it survives library updates. Arguments are user pointers,
so `read_user_str(arg(0))` reads string arguments. A `usdt` probe names
`path:provider:name`, a static marker compiled into the binary; the loader
reads the marker's note for its address, its semaphore (incremented while a
probe is attached, so the program knows to prepare marker data) and where
each argument lives, and `arg(n)` reads them through a spec at runtime.

### Packets (XDP)

An `xdp` probe sees each packet on an interface before the kernel does
anything with it. `pkt` is the packet's bytes, readable three ways:

**Raw offsets.** `pkt.u8/u16/u32(off)` at a constant offset; multi-byte
reads are converted from network to host order. `pkt.ipv6(off)` and
`pkt.mac(off)` copy an address out as bytes. `pkt.len()` is the length.

**Headers by name.** Lay a kernel struct over the bytes and read its fields:

```honey
let eth: ptr<ethhdr> = pkt.at(0);
let ip: ptr<iphdr> = pkt.at(14);
if eth.h_proto == 0x0800 && ip.protocol == 6 {
    emit Seen { src: ip.saddr, smac: eth.h_source, ihl: ip.ihl };
}
```

A field the kernel declares `__be16`/`__be32` is converted to host order; a
6- or 16-byte array or `struct in6_addr` is a `mac`/`ipv6`; an embedded
struct is another view; a bitfield such as `ip.ihl` is loaded, shifted and
masked into the narrowest integer that holds it; a pointer field is an
error. Views exist only at compile time and cost no stack or registers.

**Headers at runtime offsets.** The transport header is not at a fixed
place: IPv4's header length is `ihl * 4`, and IPv6 may have extension
headers in between.

```honey
let tcp: ptr<tcphdr> = pkt.view(14 + ip.ihl * 4);       // any integer offset

let proto = pkt.ipv6_l4(14);                              // walk the IPv6 chain
if proto == 6 {
    let tcp: ptr<tcphdr> = pkt.l4();                      // view where it stopped
    if tcp.dest == 22 { ... }
}
```

`pkt.view(expr)` bounds the offset, builds a packet pointer, and checks it
against the packet end for the struct's size once; field reads are then
plain loads. `pkt.ipv6_l4(off)` follows hop-by-hop, routing, fragment,
destination-options and AH headers (up to four, each read bounds-checked),
returns the transport protocol, and leaves the transport header's location
for `pkt.l4()`. A short packet passes through untouched at any of these
checks. One runtime view is live at a time.

**Actions and bounds.** `drop()` and `pass()` return immediately; falling off
the end passes. Every packet read must be provably in bounds or the verifier
rejects the program: honey takes the furthest constant byte the probe
touches (reads, blobs and `pkt.at` views, at most 256) and checks the packet
is at least that long once, on entry; runtime views add their own single
check. Constant offsets must be literals or `const`s.

**Subnets.** `in_subnet(addr, "10.0.0.0/8")` for a `u32` address,
`in_subnet(a6, "fe80::/10")` for an `ipv6`; the CIDR is validated at compile
time.

### Sampling

`sample(N)` is `true` on 1 of every N times it runs, backed by a counter
honey keeps per call site. Use it to thin out a high-rate hook:
`if sample(100) { emit Exec { ... }; }`.

---

## 3. Lexical structure  (normative — stage 1)

Source is UTF-8. Tokens are recognised **greedily, longest match first**, left
to right. Between tokens, whitespace and comments are skipped. The token
stream always ends with a single `Eof` token whose span is `len..len`.

Every token carries a **span**: a half-open **byte** range `[start, end)`
into the source. Bytes, not characters. The only place a multi-byte
character can legally appear is inside a string literal or a comment; anywhere
else it is an `UnexpectedChar` error whose span covers the whole character.

### 3.1 Whitespace

Space (`U+0020`), tab, line feed, carriage return. Skipped.

### 3.2 Comments

| Form                | Rule                                                         |
|---------------------|--------------------------------------------------------------|
| `// ...`            | To end of line (or end of input). Skipped.                   |
| `/* ... */`         | **Nests**: `/* a /* b */ c */` is one comment. Skipped.      |
| `/* ...` (no close) | `UnterminatedComment`, span from `/*` to end of input.       |

A lone `/` not followed by `/` or `*` is the `Slash` token.

### 3.3 Identifiers and keywords

```
ident   = ( letter | "_" ) { letter | digit | "_" } ;
letter  = "A"…"Z" | "a"…"z" ;      (* ASCII only *)
digit   = "0"…"9" ;
```

After scanning an identifier, check it against the keyword table. Keywords
are case-sensitive: `probe` is a keyword, `Probe` is an identifier. Greedy
matching means `probes` is an identifier, not `probe` + `s`.

Keywords in use:
`probe map event const let mut if else for in emit return true false as`

Keywords reserved (lexed as keywords, rejected by the parser with a useful
message):
`fn struct match while break continue`

Everything else that looks like a word is an identifier, **including** type
names (`u32`, `str`, `bool`), map kinds (`hash`, `array`), `Some`/`None`,
and builtins (`pid`, `comm`).

### 3.4 Integer literals

```
int     = dec | hex | bin | oct ;
dec     = digit { digit | "_" } ;
hex     = "0x" hexdigit { hexdigit | "_" } ;
bin     = "0b" ( "0" | "1" ) { "0" | "1" | "_" } ;
oct     = "0o" ( "0"…"7" ) { "0"…"7" | "_" } ;
```

- Underscores are separators and are ignored: `1_000_000` is `1000000`.
- The value must fit in `u64`; otherwise `IntegerOverflow`, span = the whole
  literal. `18446744073709551615` is fine, one more is an error.
- There are **no floating point literals** (eBPF has no floats). `1.5` lexes
  as `Int(1) Dot Int(5)` and the parser will reject it. Consequently `0..8`
  is unambiguous: `Int(0) DotDot Int(8)`.
- No type suffixes (`42u32` is not a thing) in v1.
- Behaviour of `0x` with no digits is unspecified for now.

### 3.5 String literals

```
string  = '"' { char | escape } '"' ;
escape  = "\n" | "\t" | "\r" | "\\" | '\"' | "\0" | "\x" hexdigit hexdigit ;
```

- The token payload is the **decoded** string.
- Any character other than `"` and `\` is taken literally, including raw
  newlines and non-ASCII.
- No closing quote before end of input: `UnterminatedString`, span from the
  opening quote to end of input.
- Backslash followed by anything not in the table: `InvalidEscape`, span
  covers the backslash and the next character.

### 3.6 Punctuation

Longest match wins. The full table:

```
(  )  {  }  [  ]  ,  ;  :  ::  .  ..  ->
=  ==  !  !=  <  <=  >  >=
+  -  *  /  %  &  &&  |  ||  ^  ~  <<  >>
```

**The `>>` question.** `hash<u32, str<16>>` ends in `>>`. The lexer emits
`Shr` there (greedy), and the *parser* splits a `Shr` into two `Gt` when it is
closing generic arguments. This is what rustc does too. It keeps the lexer
context-free at the cost of one special case in the parser.

### 3.7 Errors

The lexer returns the **first** error it meets and stops. Error kinds and
their spans are documented on `LexErrorKind` in `src/token.rs`.

---

## 4. Syntax (draft — stage 2)

EBNF. `IDENT`, `INT`, `STR` are tokens from §3.

```
program      = { item } ;
item         = const_decl | map_decl | event_decl | probe_decl ;

const_decl   = "const" IDENT ":" type "=" expr ";" ;
map_decl     = "map" IDENT ":" IDENT "<" type { "," type } ">" "[" INT "]" ";" ;
event_decl   = "event" IDENT "{" { field "," } "}" ;
field        = IDENT ":" type ;
probe_decl   = "probe" IDENT "(" STR { "," STR } ")" block ;

block        = "{" { stmt } "}" ;
stmt         = let_stmt | assign_stmt | if_stmt | for_stmt
             | emit_stmt | return_stmt | expr_stmt ;
let_stmt     = "let" [ "mut" ] IDENT [ ":" type ] "=" expr ";" ;
assign_stmt  = place "=" expr ";" ;
if_stmt      = "if" cond block [ "else" ( block | if_stmt ) ] ;
cond         = expr | "let" pattern "=" expr ;
for_stmt     = "for" IDENT "in" expr ".." expr block ;   (* bounds: const exprs *)
emit_stmt    = "emit" IDENT "{" { IDENT ":" expr "," } "}" ";" ;
return_stmt  = "return" [ expr ] ";" ;
expr_stmt    = expr ";" ;

pattern      = IDENT [ "(" IDENT ")" ] ;                (* Some(x) | None *)
place        = IDENT | "*" IDENT ;

type         = IDENT [ "<" type_arg { "," type_arg } ">" ] ;
type_arg     = type | INT ;                              (* str<64> *)

expr         = or_expr ;
or_expr      = and_expr { "||" and_expr } ;
and_expr     = eq_expr { "&&" eq_expr } ;
eq_expr      = cmp_expr { ( "==" | "!=" ) cmp_expr } ;
cmp_expr     = bor_expr { ( "<" | "<=" | ">" | ">=" ) bor_expr } ;
bor_expr     = xor_expr { "|" xor_expr } ;
xor_expr     = band_expr { "^" band_expr } ;
band_expr    = shift_expr { "&" shift_expr } ;
shift_expr   = add_expr { ( "<<" | ">>" ) add_expr } ;
add_expr     = mul_expr { ( "+" | "-" ) mul_expr } ;
mul_expr     = cast_expr { ( "*" | "/" | "%" ) cast_expr } ;
cast_expr    = unary_expr [ "as" type ] ;
unary_expr   = ( "!" | "-" | "~" | "*" ) unary_expr | postfix_expr ;
postfix_expr = primary { "(" [ args ] ")" | "." IDENT | "[" expr "]" } ;
args         = expr { "," expr } ;
primary      = INT | STR | "true" | "false" | IDENT | "(" expr ")" ;
```

Precedence, lowest to highest: `||`, `&&`, `== !=`, `< <= > >=`, `|`, `^`,
`&`, `<< >>`, `+ -`, `* / %`, `as`, unary, postfix. Same as Rust.

## 5. Types (normative — stage 4)

| Type                    | Notes                                                    |
|-------------------------|----------------------------------------------------------|
| `u8 u16 u32 u64`        | Unsigned. No implicit conversions between widths; an unsuffixed literal adapts to the width it meets and is range-checked. |
| `i64`                   | Signed; the type of `retval()`. Compared with signed jumps. Never mixes with unsigned widths implicitly. |
| `bool`                  | Conditions must be `bool`; `&& \|\| !` take `bool`.       |
| `str<N>`                | Fixed-capacity byte string on the BPF stack, 1 ≤ N ≤ 256. Only `read_user_str` (and `comm()` in an `emit`) can produce one. |
| `hash<K, V>`, `array<V>`| Map kinds, only in `map` declarations. K and V are integers or bool. |
| `Option<&V>`            | The result of `map.get`. Not user-writable. Must be matched with `if let Some(v)` / `if let None`. |
| `&V`                    | A checked pointer, only bound by `if let Some(v)` and only inside that block. `*v` reads it. |
| `ipv4`                  | A `u32` to the type system, printed by the loader as a dotted quad (`127.0.0.1`). Assign from `pkt.u32(...)`. |
| `ipv6`, `mac`           | 16- and 6-byte values copied straight from the packet with `pkt.ipv6(off)` / `pkt.mac(off)`. Bind with `let`, compare with `==`/`!=` against a literal (`"::1"`, `"aa:bb:cc:dd:ee:ff"`) or another address of the same kind, emit; printed as addresses. Cannot be reassigned and cannot live in maps. |
| `ptr<S>`                | A kernel pointer to `struct S` (a real kernel type, checked against BTF). From `let p: ptr<S> = arg(n);`. Read fields with `.` (pointers auto-deref). In an `xdp` probe, `let v: ptr<S> = pkt.at(off)` / `pkt.view(expr)` / `pkt.l4()` is instead a *view* of packet bytes: fields are read by value, never followed. |

Verifier-safety rules the checker enforces (see `docs/STAGE-4.md`):

- **Bounded loops only.** `for i in a..b` requires `a` and `b` to be
  compile-time constants (literals, `const`s, loop variables, and `+ - * | & <<`
  over them) with `b - a ≤ 64`. There is no `while`.
- **Checked map access.** `map.get(k)` is `Option<&V>`; `*` on it is an error,
  and the `Some(v)` binding does not outlive its `if`.
- **Bounded reads.** `read_user_str(p)` must initialise `let s: str<N>`;
  `s.byte_at(i)` needs constant `i < N`; `s.starts_with("...")` needs a literal
  no longer than `N`.
- **String equality.** `s == "lit"`, `s != "lit"`, and `s == t` between two
  `str<N>` values compare as C strings: equal through the terminating NUL,
  bounded by the capacities, fully unrolled. A literal longer than `N` is a
  compile-time error (it could never match); `<`/`>` on strings are errors.
- **Address equality.** `ipv6`/`mac` values compare with `==`/`!=` against a
  literal or another address of the same kind (unrolled chunk compares); a
  `u32` address compares against a dotted quad (`ip == "10.0.0.1"`). Address
  literals are validated at compile time, so a typo is an error rather than
  a rule that never matches. Kinds never mix (`ipv6` vs `mac` is an error).
- **Stack budget.** Locals are 8 bytes (scalars, pointers) or `N` rounded to 8
  (`str<N>`), summed along each scope path. Peak + 40 bytes reserve ≤ 512.
- **No pointer writes** in v1: `*p = v` is rejected, use `map.insert`.
- **Immutability.** Assignment needs `let mut`.

## 6. Builtins

| Builtin                                   | Type                       | Where              | Underneath |
|-------------------------------------------|----------------------------|--------------------|------------|
| `pid()`, `tgid()`, `tid()`                | `u32`                      | not xdp            | `bpf_get_current_pid_tgid` |
| `uid()`, `gid()`                          | `u32`                      | not xdp            | `bpf_get_current_uid_gid` |
| `comm()`                                  | `str<16>` (emit field only)| not xdp            | `bpf_get_current_comm` |
| `ktime()`                                 | `u64`                      | anywhere           | `bpf_ktime_get_ns` |
| `arg(n)`                                  | `u64`                      | tracepoint, kprobe, uprobe, usdt, lsm | record field / `pt_regs` / USDT spec / hook args |
| `retval()`                                | `i64`                      | kretprobe, uretprobe | the return register |
| `read_user_str(p)`                        | `str<N>` (from the let)    | anywhere           | `bpf_probe_read_user_str` |
| `read_kernel_str(p)`                      | `str<N>` (from the let)    | anywhere           | `bpf_probe_read_kernel_str` |
| `m.get(k)` / `m.insert(k, v)` / `m.delete(k)` | `Option<&V>` / `()`    | anywhere           | `bpf_map_lookup/update/delete_elem` |
| `emit E { … }`                            | statement                  | anywhere           | `bpf_ringbuf_reserve/submit` |
| `deny()` / `allow()`                      | statement                  | lsm                | return -EPERM / 0 |
| `drop()` / `pass()`                       | statement                  | xdp                | XDP_DROP / XDP_PASS |
| `sample(N)`                               | `bool`                     | anywhere           | a hidden per-site counter map |
| `in_subnet(addr, "cidr")`                 | `bool`                     | anywhere           | mask-and-compare, folded at compile time |
| `s.starts_with("…")`, `s.byte_at(i)`      | `bool` / `u8`              | anywhere           | unrolled, bounded by `N` |
| `s == "…"`, `s != t`, `a == "::1"`, `ip == "1.2.3.4"` | `bool`         | anywhere           | unrolled equality; literals validated |
| `pkt.u8/u16/u32(off)`, `pkt.len()`        | ints                       | xdp                | bounded loads, host order |
| `pkt.ipv6(off)`, `pkt.mac(off)`           | `ipv6`, `mac`              | xdp                | byte copies |
| `pkt.at(off)`, `pkt.view(expr)`, `pkt.l4()` | `ptr<S>` view (via `let`) | xdp               | struct layouts from BTF |
| `pkt.ipv6_l4(off)`                        | `u8`                       | xdp                | 4-hop extension-header walk |

## 7. Status

Every stage is done and every feature above is verified against a live
kernel (`examples/*.hny`, each with the evidence in its commit message):

| Stage | Deliverable                                                          |
|-------|----------------------------------------------------------------------|
| 1     | Lexer                                                                |
| 2     | Parser → AST, pretty-printer                                         |
| 3     | Bytecode emitter + disassembler, C loader; every probe kind; CO-RE-style struct reads; packet views; register allocator |
| 4     | Verifier-aware type checker: `honeyc check`, every rule an error at the source line, `examples/bad/` one program per rule |

Not done, and not planned for v1: writing packet fields or checksums, more
than one live runtime view, TCP option parsing, IPv6 in maps, functions.

## 8. Decisions taken along the way

- String and address equality *are* allowed (`==`/`!=`), unrolled and
  bounded; `<`/`>` on them are not.
- Rate limiting is a builtin: `sample(N)`.
- kprobe/uprobe argument offsets are per architecture (`--arch`, default
  aarch64); the manifest records the arch and the loader warns on mismatch.
- USDT arguments are resolved at attach time into a runtime spec rather than
  at compile time, so one compiled probe works wherever the marker's
  arguments happen to live.
- The register allocator does not shrink instruction counts (BPF has no
  memory-operand ALU forms); it removes stack traffic and stack use.
