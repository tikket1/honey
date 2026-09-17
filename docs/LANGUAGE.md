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

| Probe                              | Hook                                    | Available |
|------------------------------------|-----------------------------------------|-----------|
| `tracepoint("syscalls", "sys_enter_openat")` | a static kernel tracepoint    | `arg(n)`  |
| `kprobe("do_sys_openat2")`         | entry of a kernel function              | `arg(n)`  |
| `kretprobe("do_sys_openat2")`      | return of a kernel function             | `retval()`|

A tracepoint sees the *request*; to know the *result* hook the function with
a `kprobe` and a `kretprobe` and correlate them through a map keyed by
`tid()` (see `examples/shadow_open_ok.hny`).

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
| `ptr<S>`                | A kernel pointer to `struct S` (a real kernel type, checked against BTF). From `let p: ptr<S> = arg(n);`. Read fields with `.` (pointers auto-deref). |

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

## 6. Builtins (draft — stage 3 makes them real)

| Builtin                    | Type                              | BPF helper / source           |
|----------------------------|-----------------------------------|-------------------------------|
| `pid()`                    | `u32`                             | `bpf_get_current_pid_tgid`    |
| `tgid()`                   | `u32`                             | `bpf_get_current_pid_tgid`    |
| `uid()`                    | `u32`                             | `bpf_get_current_uid_gid`     |
| `comm()`                   | `str<16>`                         | `bpf_get_current_comm`        |
| `ktime()`                  | `u64`                             | `bpf_ktime_get_ns`            |
| `arg(n)`                   | `u64`                             | tracepoint: record field `n`; kprobe: `pt_regs` argument `n` (per arch); not in kretprobe |
| `retval()`                 | `i64`                             | kretprobe only: the return register (`x0` / `rax`) |
| `tid()`                    | `u32`                             | `bpf_get_current_pid_tgid` low half; key for kprobe↔kretprobe correlation |
| `read_user_str(p)`         | `str<N>` (N from the let type)    | `bpf_probe_read_user_str`     |
| `m.get(k)` / `m.insert(k,v)` | `Option<&V>` / `()`             | `bpf_map_lookup/update_elem`  |
| `emit E { … }`             | statement                         | `bpf_ringbuf_output`          |
| `s.starts_with("…")`, `s.byte_at(i)` | `bool` / `u8`           | inline, bounded by `N`        |
| `s == "…"`, `s != t`       | `bool`                            | exact C-string equality, unrolled, bounded by `N` |
| `a == "::1"`, `m != n`, `ip == "1.2.3.4"` | `bool`             | address equality: ipv6/mac chunk compares; a dotted quad is a `u32` literal |

## 7. Roadmap

| Stage | Deliverable                                                            | Runs on   |
|-------|------------------------------------------------------------------------|-----------|
| 1     | Lexer. `cargo test` green in `crates/honeyc`.                           | macOS     |
| 2     | Parser → AST. Pretty-printer for round-trip tests.                     | macOS     |
| 3     | Bytecode emitter + disassembler; C loader. Done: all three examples run in-kernel (maps, control flow, arithmetic, bounded `for`, strings, `arg`). | Docker Linux |
| 4     | Verifier-aware type checker: the rules in §5. Done: `honeyc check`, all errors at source lines, `examples/bad/` demonstrates each rule. | macOS |

Non-goals for v1: enforcement (LSM), networking (XDP), CO-RE/BTF relocation,
anything that needs a heap.

## 8. Open questions (decide when they bite)

- Should `str<N>` comparisons (`==`) be allowed, or only `starts_with`?
- Does `emit` need a rate limit / sampling primitive built in?
- kprobe argument offsets are per architecture (`--arch aarch64|x86_64`);
  the manifest records the arch and the loader warns on mismatch.
