# Stage 1 — the lexer

**Goal:** make every test in `crates/honeyc/tests/lexer.rs` pass by writing
`crates/honeyc/src/lexer.rs`. Nothing else needs to change.

**Contract:** `src/token.rs` (read it, do not edit it) and
`docs/LANGUAGE.md` § 3 (the rules).

**You write the code.** This document tells you what to read, the order to
attack the tests in, the Rust you will need, and the traps.

---

## Before you start

Rust Book chapters 1–9 cover everything a lexer needs. If you read nothing
else, read:

- ch 4 (ownership, `String` vs `&str`) — you will hold a `&str` and produce
  `String`s for identifiers.
- ch 6 (enums, `match`, `Option`) — `TokenKind` is an enum; `peek()` returns
  an `Option<char>`.
- ch 8.2 (strings) — **why byte offsets and char offsets differ**. Read this
  twice. It is the single most common lexer bug in Rust.
- ch 9 (`Result`, `?`) — `lex` returns `Result<Vec<Token>, LexError>`.

Crafting Interpreters ch 4 ("Scanning") is the same exercise in Java; skim it
for the *shape*, then write the Rust yourself.

## Run one test at a time

```bash
cd ~/GitHub/honey
cargo test --test lexer                       # everything (all fail right now)
cargo test --test lexer empty_input           # one test
cargo test --test lexer -- --nocapture        # see println! output
```

The test file is ordered easiest → hardest. Work top to bottom.

## Suggested order of attack

1. **`empty_input_is_just_eof`** — return `vec![Eof at len..len]`. Now you
   have the skeleton: a `Lexer` struct, a `pos`, a `tokens` vec, a main loop.
2. **Whitespace** — skip it in the main loop.
3. **Single-char punctuation** — a big `match` on the char. Push a token with
   span `start..start+1`.
4. **Identifiers, then keywords** — scan `[A-Za-z_][A-Za-z0-9_]*`, then look
   the word up in a keyword table (`match` on `&str` works fine).
5. **Multi-char punctuation** — when you see `=`, peek at the next char: is it
   `=`? This is the "longest match" rule. Order matters: check `..` before `.`.
6. **Decimal integers** — collect digits and `_`, strip `_`, parse with
   `u64::from_str_radix(…, 10)`. Its `Err` is your `IntegerOverflow`.
7. **Hex / bin / oct** — if the literal starts `0x`/`0b`/`0o`, skip the prefix
   and use radix 16 / 2 / 8.
8. **Comments** — `//` is easy. `/* */` needs a depth counter for nesting.
9. **Strings** — a loop that handles `\` specially. Build the decoded
   `String` as you go; `\xNN` needs two hex digits → `u8` → `char`.
10. **Errors** — the `Unterminated*`, `InvalidEscape`, `UnexpectedChar` tests.
11. **Spans and unicode** — if you have been working in *byte* offsets all
    along these pass for free. If you have been counting chars, they won't.

## Rust you will need (and pitfalls)

**Bytes vs chars.** Every token honey has is ASCII, so you can scan with
`src.as_bytes()[pos]` and `pos += 1` for the happy path. But `UnexpectedChar`
must report the *char* (`'é'`, not the byte `0xC3`) and its span must cover
all its bytes. Easiest: `src[pos..].chars().next()` gives you the char, and
`c.len_utf8()` gives you how many bytes to skip. Slicing a `&str` in the
middle of a multi-byte char panics — but if you only ever advance by
`len_utf8()` you will never be in the middle.

**`peek` / `bump`.** Two small methods on the `Lexer` struct make everything
readable. `peek` looks without consuming, `bump` consumes and returns. Write
them first.

**Owning the identifier.** `&src[start..pos]` is a `&str` borrowed from the
input. `TokenKind::Ident` wants a `String` it owns: `.to_string()` or
`.to_owned()`.

**Returning early with `?`.** Make the per-token helpers return
`Result<(), LexError>` and use `?` in the main loop so an error unwinds
cleanly.

**Lifetimes.** `struct Lexer<'a> { src: &'a str, … }` is the first lifetime
you'll write. It only says "this struct can't outlive the string it borrows".
The compiler will tell you exactly where to put the `'a`s.

## The `>>` trap

`hash<u32, str<16>>` ends in `>>`. Emit `Shr`. Don't try to be clever in the
lexer; the parser will split it. There is a test that pins this behaviour.

## Done when

- `cargo test` is green.
- `cargo run -- examples/sensitive_open.hny` prints a token per line and
  exits 0.
- `cargo clippy` has nothing to say (install with `rustup component add clippy`).

Then tell me and I'll review it before we start stage 2 (the parser).
