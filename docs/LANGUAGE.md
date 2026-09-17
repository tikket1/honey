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
declarations. Each `probe` becomes one BPF program; the userspace loader
(stage 3) attaches it and prints the events.

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

## 5. Types (draft — stage 4 owns the interesting parts)

| Type                    | Notes                                                    |
|-------------------------|----------------------------------------------------------|
| `u8 u16 u32 u64`        | Unsigned. BPF registers are 64-bit; narrower = masked.    |
| `i8 i16 i32 i64`        | Signed.                                                   |
| `bool`                  | 0 or 1 in a register.                                     |
| `str<N>`                | Fixed-capacity, NUL-padded byte string on the BPF stack.  |
| `hash<K, V>`, `array<V>`| Map kinds. Only valid in `map` declarations.              |
| `Option<&V>`            | Result of `map.get`. Must be matched before use.          |
| `ptr<T>` *(later)*      | Raw kernel/user pointer; only readable via bounded helpers.|

Verifier-safety rules the type checker enforces (this is the research bit):

- **Bounded loops only.** `for i in a..b` requires `a` and `b` to be
  compile-time constants and `b - a` below a fixed limit. There is no `while`.
- **Checked map access.** `map.get(k)` returns `Option<&V>`; the only way to
  read the value is `if let Some(v) = …`. This is exactly the null check the
  verifier insists on, moved to compile time.
- **Bounded reads.** `read_user_str(p)` needs a `str<N>` destination, so the
  bound `N` is always known to the helper call.
- **Stack budget.** BPF gives 512 bytes of stack. The sum of all locals'
  sizes in a probe is checked at compile time; exceeding it is a type error.
- **No pointer arithmetic** in v1. Pointers come from helpers and go to
  helpers.

## 6. Builtins (draft — stage 3 makes them real)

| Builtin                    | Type                              | BPF helper / source           |
|----------------------------|-----------------------------------|-------------------------------|
| `pid()`                    | `u32`                             | `bpf_get_current_pid_tgid`    |
| `tgid()`                   | `u32`                             | `bpf_get_current_pid_tgid`    |
| `uid()`                    | `u32`                             | `bpf_get_current_uid_gid`     |
| `comm()`                   | `str<16>`                         | `bpf_get_current_comm`        |
| `ktime()`                  | `u64`                             | `bpf_ktime_get_ns`            |
| `arg(n)`                   | `u64`                             | tracepoint context field `n`  |
| `read_user_str(p)`         | `str<N>` (N from the let type)    | `bpf_probe_read_user_str`     |
| `m.get(k)` / `m.insert(k,v)` | `Option<&V>` / `()`             | `bpf_map_lookup/update_elem`  |
| `emit E { … }`             | statement                         | `bpf_ringbuf_output`          |
| `s.starts_with("…")`, `s.byte_at(i)` | `bool` / `u8`           | inline, bounded by `N`        |

## 7. Roadmap

| Stage | Deliverable                                                            | Runs on   |
|-------|------------------------------------------------------------------------|-----------|
| 1     | Lexer. `cargo test` green in `crates/honeyc`.                           | macOS     |
| 2     | Parser → AST. Pretty-printer for round-trip tests.                     | macOS     |
| 3     | Bytecode emitter + disassembler; C loader. Done: all three examples run in-kernel (maps, control flow, arithmetic, bounded `for`, strings, `arg`). | Docker Linux |
| 4     | Verifier-aware type checker: the rules in §5. Illegal-to-verify = illegal-to-typecheck. | both |

Non-goals for v1: enforcement (LSM), networking (XDP), CO-RE/BTF relocation,
anything that needs a heap.

## 8. Open questions (decide when they bite)

- Should `str<N>` comparisons (`==`) be allowed, or only `starts_with`?
- Does `emit` need a rate limit / sampling primitive built in?
- kprobe argument access: `arg(n)` is enough for tracepoints; kprobes need
  the pt_regs layout per architecture.
