# Stage 4 — the verifier-aware type checker

This is the part of honey that is not just a compiler exercise. The kernel's
BPF verifier is a static analyser that rejects programs it cannot prove safe.
Its rules are few and well known, but in C they are enforced *after* you have
compiled, on the generated instructions, with errors that name an instruction
index rather than a line of your code. Stage 4 restates each rule as a
type-system or scoping rule in honey's checker, so that:

- a program that passes `honeyc check` is one the verifier will accept, and
- a program the verifier would reject fails `honeyc check` at the source line
  that caused it, with a hint for the fix.

Run it on its own with `honeyc check file.hny`. `build` and `--asm` run it
first and refuse to generate code for anything that fails.

## The rules

| Verifier rule (what it rejects)                | honey rule (where it is caught)                                  |
|------------------------------------------------|-------------------------------------------------------------------|
| loops that can't be proven to terminate        | `for` bounds must be compile-time constants; at most 64 iterations; there is no `while` |
| using a map lookup result before its NULL check| `map.get` has type `Option<&V>`. The only way to reach the `&V` is `if let Some(v) = ...`. `*` on an `Option` is a type error with the fix in the message |
| using a checked pointer after the check's scope| the `Some(v)` binding exists only inside that `if` body; outside it is an unknown name |
| reads of unknown length into the stack         | `read_user_str` may only initialise a declared `str<N>`; `N` is the read bound and cannot be omitted |
| out-of-range stack access                      | `byte_at(i)` needs a constant `i < N`; `starts_with` literal must fit in `N` |
| more than 512 bytes of stack                   | locals are summed along each scope path; the peak plus the compiler's reserve must fit, or it is an error naming the numbers |
| writes through map value pointers (v1 choice)  | `*p = v` is rejected; `map.insert` is the supported update |
| unsafe integer truncation                      | four unsigned widths plus `i64`, no implicit conversion; mixing widths is a type error and literals are range-checked |
| reading arguments after they are gone          | `arg(n)` is rejected in a `kretprobe`; `retval()` is rejected everywhere but a `kretprobe` |

Everything else is ordinary static typing: `bool` conditions, event fields
set exactly once with the right types, map key/value types on every access,
immutability unless `let mut`, known names, valid builtins and arities.

## What it looks like

`examples/bad/unchecked_map.hny` dereferences a lookup without checking it:

```
$ honeyc check examples/bad/unchecked_map.hny
examples/bad/unchecked_map.hny:12:13: error: cannot dereference `Option<&u64>`: the lookup may have found nothing
        let n = *prev + 1;
                ^
    help: check it first: `if let Some(v) = map.get(key) { ... *v ... }`
```

The same program in C loads and is rejected by the verifier with
`R0 invalid mem access 'map_value_or_null'` at an instruction offset. Every
file in `examples/bad/` is one such case; the first line of each is the error
honey gives, and the test suite checks it.

All errors in a file are reported together, not just the first.

## Design notes

- **Types.** `u8 u16 u32 u64 bool str<N>`, plus two internal types the user
  never writes: `Option<&V>` (a lookup result) and `&V` (a checked pointer).
  `{integer}` is an unsuffixed literal that adapts to the width it meets.
- **Scopes carry stack.** Each scope records the bytes of its locals; the
  checker tracks the running total and its peak. Sibling scopes reuse stack,
  nested scopes add. This mirrors how codegen lays the frame out, so the
  checker's number is what codegen will use.
- **Constants.** `const` values, integer literals, and loop variables are
  compile-time constants and can be combined with `+ - * | & <<` where a
  constant is required.
- **Reserve.** The checker leaves 40 bytes of the 512 for codegen's saved
  context pointer and spill slots. Codegen still measures its exact usage as
  a backstop.
- **Order.** The checker runs on the AST before codegen and produces
  diagnostics only; codegen keeps its own lightweight width tracking. A later
  refactor could hand codegen a typed AST, but keeping them separate keeps
  each readable.

## What is deliberately not here yet

- LSM and XDP probe kinds; uprobes.
- Functions.
- `as` casts, signed widths other than `i64`, in-place map updates, string equality.
- Rate limiting or sampling for `emit`.

Each of these is an addition to the same checker, not a redesign.
