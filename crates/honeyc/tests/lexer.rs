//! Stage 1 acceptance tests. Ordered easiest → hardest; work top to bottom.
//!
//! Run one:   cargo test --test lexer empty_input
//! Run all:   cargo test --test lexer
//!
//! Rules under test: docs/LANGUAGE.md § 3. Types: src/token.rs.

use TokenKind::*;
use honeyc::lexer::lex;
use honeyc::token::{LexError, LexErrorKind, Span, Token, TokenKind};

// ---------------------------------------------------------------- helpers

/// Lex, assert the stream ends in Eof, return the kinds *without* the Eof.
fn kinds(src: &str) -> Vec<TokenKind> {
    let toks = lex(src).unwrap_or_else(|e| panic!("lex({src:?}) failed: {e:?}"));
    assert_eq!(toks.last().map(|t| &t.kind), Some(&Eof), "token stream must end with Eof: {toks:?}");
    toks.into_iter().map(|t| t.kind).filter(|k| *k != Eof).collect()
}

/// Lex something that must fail; return the error.
fn err(src: &str) -> LexError {
    match lex(src) {
        Ok(toks) => panic!("lex({src:?}) should have failed, got {toks:?}"),
        Err(e) => e,
    }
}

fn ident(s: &str) -> TokenKind {
    Ident(s.to_string())
}

fn string(s: &str) -> TokenKind {
    Str(s.to_string())
}

fn sp(start: usize, end: usize) -> Span {
    Span::new(start, end)
}

// ----------------------------------------------------------- 1. skeleton

#[test]
fn empty_input_is_just_eof() {
    assert_eq!(lex("").unwrap(), vec![Token { kind: Eof, span: sp(0, 0) }]);
}

#[test]
fn whitespace_only_is_just_eof() {
    let src = "  \t\n\r\n ";
    assert_eq!(lex(src).unwrap(), vec![Token { kind: Eof, span: sp(src.len(), src.len()) }]);
}

// ----------------------------------------------- 2. single-char punctuation

#[test]
fn single_char_punctuation() {
    assert_eq!(
        kinds("( ) { } [ ] , ; : . = ! < > + - * / % & | ^ ~"),
        vec![
            LParen, RParen, LBrace, RBrace, LBracket, RBracket, Comma, Semi, Colon, Dot, Eq, Bang, Lt, Gt, Plus, Minus, Star, Slash,
            Percent, Amp, Pipe, Caret, Tilde,
        ]
    );
}

#[test]
fn punctuation_needs_no_whitespace() {
    assert_eq!(kinds("(){}[];,"), vec![LParen, RParen, LBrace, RBrace, LBracket, RBracket, Semi, Comma]);
}

// --------------------------------------------------- 3. identifiers & keywords

#[test]
fn single_identifier() {
    assert_eq!(kinds("foo"), vec![ident("foo")]);
}

#[test]
fn identifiers_allow_underscores_and_digits() {
    assert_eq!(
        kinds("_ _x x1 foo_bar __init sys_enter_execve u32"),
        vec![ident("_"), ident("_x"), ident("x1"), ident("foo_bar"), ident("__init"), ident("sys_enter_execve"), ident("u32"),]
    );
}

#[test]
fn every_keyword() {
    let table = [
        ("probe", Probe),
        ("map", Map),
        ("event", Event),
        ("const", Const),
        ("let", Let),
        ("mut", Mut),
        ("if", If),
        ("else", Else),
        ("for", For),
        ("in", In),
        ("emit", Emit),
        ("return", Return),
        ("true", True),
        ("false", False),
        ("as", As),
        // reserved
        ("fn", Fn),
        ("struct", Struct),
        ("match", Match),
        ("while", While),
        ("break", Break),
        ("continue", Continue),
    ];
    for (src, expected) in table {
        assert_eq!(kinds(src), vec![expected.clone()], "keyword {src:?}");
    }
}

#[test]
fn keywords_are_case_sensitive() {
    assert_eq!(kinds("Probe PROBE probe"), vec![ident("Probe"), ident("PROBE"), Probe]);
}

#[test]
fn identifier_with_keyword_prefix_is_an_identifier() {
    assert_eq!(kinds("probes mapping iffy letter"), vec![ident("probes"), ident("mapping"), ident("iffy"), ident("letter")]);
}

#[test]
fn type_names_and_builtins_are_plain_identifiers() {
    assert_eq!(
        kinds("hash array str bool Some None pid"),
        vec![ident("hash"), ident("array"), ident("str"), ident("bool"), ident("Some"), ident("None"), ident("pid"),]
    );
}

// ------------------------------------------------- 4. multi-char punctuation

#[test]
fn multi_char_punctuation() {
    assert_eq!(
        kinds(":: .. -> == != <= >= && || << >>"),
        vec![ColonColon, DotDot, Arrow, EqEq, BangEq, LtEq, GtEq, AmpAmp, PipePipe, Shl, Shr]
    );
}

#[test]
fn longest_match_wins() {
    assert_eq!(kinds("a==b"), vec![ident("a"), EqEq, ident("b")]);
    assert_eq!(kinds("x<=y"), vec![ident("x"), LtEq, ident("y")]);
    assert_eq!(kinds("a->b"), vec![ident("a"), Arrow, ident("b")]);
    assert_eq!(kinds("a::b"), vec![ident("a"), ColonColon, ident("b")]);
    assert_eq!(kinds("a&&b||c"), vec![ident("a"), AmpAmp, ident("b"), PipePipe, ident("c")]);
}

#[test]
fn separated_chars_stay_separate() {
    // A space breaks the match: this is `!` then `=`, not `!=`.
    assert_eq!(kinds("! ="), vec![Bang, Eq]);
    assert_eq!(kinds("- >"), vec![Minus, Gt]);
    assert_eq!(kinds(": :"), vec![Colon, Colon]);
}

#[test]
fn three_in_a_row_is_greedy_then_single() {
    // `===` has no meaning in honey; greedy lexing yields `==` then `=`.
    assert_eq!(kinds("==="), vec![EqEq, Eq]);
    assert_eq!(kinds("..."), vec![DotDot, Dot]);
}

#[test]
fn shr_is_greedy_even_when_closing_generics() {
    // The lexer does NOT know about generics. `str<16>>` ends in `Shr`, and
    // the parser is responsible for splitting it. (rustc does the same.)
    assert_eq!(kinds("hash<u32, str<16>>"), vec![ident("hash"), Lt, ident("u32"), Comma, ident("str"), Lt, Int(16), Shr]);
}

// ------------------------------------------------------------- 5. integers

#[test]
fn decimal_integers() {
    assert_eq!(kinds("0 7 42 1024"), vec![Int(0), Int(7), Int(42), Int(1024)]);
}

#[test]
fn underscores_are_ignored_in_integers() {
    assert_eq!(kinds("1_000_000 4_096"), vec![Int(1_000_000), Int(4_096)]);
}

#[test]
fn hex_integers() {
    assert_eq!(kinds("0xFF 0xff 0x0 0xDEAD_BEEF"), vec![Int(0xFF), Int(0xFF), Int(0), Int(0xDEAD_BEEF)]);
}

#[test]
fn binary_integers() {
    assert_eq!(kinds("0b1010 0b0 0b1111_0000"), vec![Int(10), Int(0), Int(0b1111_0000)]);
}

#[test]
fn octal_integers() {
    assert_eq!(kinds("0o755 0o100"), vec![Int(0o755), Int(0o100)]);
}

#[test]
fn u64_max_fits() {
    assert_eq!(kinds("18446744073709551615"), vec![Int(u64::MAX)]);
    assert_eq!(kinds("0xFFFF_FFFF_FFFF_FFFF"), vec![Int(u64::MAX)]);
}

#[test]
fn u64_overflow_is_an_error() {
    let src = "18446744073709551616"; // u64::MAX + 1, 20 chars
    let e = err(src);
    assert_eq!(e.kind, LexErrorKind::IntegerOverflow);
    assert_eq!(e.span, sp(0, 20));

    let e = err("0x1_0000_0000_0000_0000");
    assert_eq!(e.kind, LexErrorKind::IntegerOverflow);
    assert_eq!(e.span, sp(0, 23));
}

#[test]
fn integer_followed_by_dotdot_is_a_range() {
    assert_eq!(kinds("0..8"), vec![Int(0), DotDot, Int(8)]);
    assert_eq!(kinds("0..N"), vec![Int(0), DotDot, ident("N")]);
}

#[test]
fn there_are_no_float_literals() {
    // eBPF has no floats. `1.5` is three tokens; the parser rejects it.
    assert_eq!(kinds("1.5"), vec![Int(1), Dot, Int(5)]);
}

// ------------------------------------------------------------- 6. comments

#[test]
fn line_comment_is_skipped() {
    assert_eq!(kinds("a // this is ignored\nb"), vec![ident("a"), ident("b")]);
}

#[test]
fn line_comment_at_end_of_input_without_newline() {
    assert_eq!(kinds("a // trailing"), vec![ident("a")]);
}

#[test]
fn block_comment_is_skipped() {
    assert_eq!(kinds("a /* ignored */ b"), vec![ident("a"), ident("b")]);
    assert_eq!(kinds("a /* multi\nline */ b"), vec![ident("a"), ident("b")]);
}

#[test]
fn block_comments_nest() {
    assert_eq!(kinds("/* a /* b */ c */ x"), vec![ident("x")]);
    assert_eq!(kinds("/* /* /* */ */ */ y"), vec![ident("y")]);
}

#[test]
fn unterminated_block_comment_is_an_error() {
    let src = "/* never closed"; // 15 bytes
    let e = err(src);
    assert_eq!(e.kind, LexErrorKind::UnterminatedComment);
    assert_eq!(e.span, sp(0, 15));

    // Nesting counts: one `*/` is not enough to close two `/*`.
    let src = "/* outer /* inner */ still open";
    let e = err(src);
    assert_eq!(e.kind, LexErrorKind::UnterminatedComment);
    assert_eq!(e.span, sp(0, src.len()));
}

#[test]
fn lone_slash_is_division() {
    assert_eq!(kinds("a / b"), vec![ident("a"), Slash, ident("b")]);
    assert_eq!(kinds("a/b"), vec![ident("a"), Slash, ident("b")]);
}

// -------------------------------------------------------------- 7. strings

#[test]
fn simple_string() {
    assert_eq!(kinds(r#""hello""#), vec![string("hello")]);
}

#[test]
fn empty_string() {
    assert_eq!(kinds(r#""""#), vec![string("")]);
}

#[test]
fn string_escapes_are_decoded() {
    // Source text is:  "a\nb\t\\\"\0"   (backslash sequences, not real newlines)
    let src = r#""a\nb\t\\\"\0""#;
    assert_eq!(kinds(src), vec![string("a\nb\t\\\"\0")]);
    assert_eq!(kinds(r#""\r""#), vec![string("\r")]);
}

#[test]
fn hex_escapes_are_decoded() {
    assert_eq!(kinds(r#""\x41\x7a""#), vec![string("Az")]);
    assert_eq!(kinds(r#""\x00""#), vec![string("\0")]);
}

#[test]
fn raw_newline_inside_string_is_allowed() {
    assert_eq!(kinds("\"a\nb\""), vec![string("a\nb")]);
}

#[test]
fn non_ascii_inside_string_is_allowed() {
    assert_eq!(kinds(r#""héllo 🔥""#), vec![string("héllo 🔥")]);
}

#[test]
fn strings_next_to_punctuation() {
    assert_eq!(
        kinds(r#"tracepoint("syscalls", "sys_enter_execve")"#),
        vec![ident("tracepoint"), LParen, string("syscalls"), Comma, string("sys_enter_execve"), RParen,]
    );
}

#[test]
fn unterminated_string_is_an_error() {
    let e = err(r#""abc"#);
    assert_eq!(e.kind, LexErrorKind::UnterminatedString);
    assert_eq!(e.span, sp(0, 4));

    let src = "let s = \"oops;\nlet t = 1;";
    let e = err(src);
    assert_eq!(e.kind, LexErrorKind::UnterminatedString);
    assert_eq!(e.span, sp(8, src.len()));
}

#[test]
fn invalid_escape_is_an_error() {
    let e = err(r#""\q""#); // bytes: " \ q "
    assert_eq!(e.kind, LexErrorKind::InvalidEscape);
    assert_eq!(e.span, sp(1, 3));

    let e = err(r#""ab\z""#);
    assert_eq!(e.kind, LexErrorKind::InvalidEscape);
    assert_eq!(e.span, sp(3, 5));
}

// ---------------------------------------------------------------- 8. spans

#[test]
fn spans_are_byte_offsets() {
    // let x = 42;
    // 0123456789A
    let toks = lex("let x = 42;").unwrap();
    assert_eq!(
        toks,
        vec![
            Token { kind: Let, span: sp(0, 3) },
            Token { kind: ident("x"), span: sp(4, 5) },
            Token { kind: Eq, span: sp(6, 7) },
            Token { kind: Int(42), span: sp(8, 10) },
            Token { kind: Semi, span: sp(10, 11) },
            Token { kind: Eof, span: sp(11, 11) },
        ]
    );
}

#[test]
fn spans_cover_whole_multi_char_tokens() {
    let toks = lex("0xFF_00 >>= \"hi\"").unwrap();
    assert_eq!(toks[0], Token { kind: Int(0xFF00), span: sp(0, 7) });
    assert_eq!(toks[1], Token { kind: Shr, span: sp(8, 10) });
    assert_eq!(toks[2], Token { kind: Eq, span: sp(10, 11) });
    assert_eq!(toks[3], Token { kind: string("hi"), span: sp(12, 16) });
}

#[test]
fn spans_count_bytes_not_chars() {
    // "é" is 1 char but 2 bytes, so the string token is 4 bytes wide and
    // `x` starts at byte 5, not 3.
    let toks = lex("\"é\" x").unwrap();
    assert_eq!(toks[0], Token { kind: string("é"), span: sp(0, 4) });
    assert_eq!(toks[1], Token { kind: ident("x"), span: sp(5, 6) });
    assert_eq!(toks[2], Token { kind: Eof, span: sp(6, 6) });
}

#[test]
fn spans_survive_comments_and_newlines() {
    let src = "a /* c */\n  b";
    let toks = lex(src).unwrap();
    assert_eq!(toks[0], Token { kind: ident("a"), span: sp(0, 1) });
    assert_eq!(toks[1], Token { kind: ident("b"), span: sp(12, 13) });
}

// ------------------------------------------------------- 9. bad characters

#[test]
fn unexpected_ascii_char_is_an_error() {
    let e = err("@");
    assert_eq!(e.kind, LexErrorKind::UnexpectedChar('@'));
    assert_eq!(e.span, sp(0, 1));

    let e = err("let $x = 1;");
    assert_eq!(e.kind, LexErrorKind::UnexpectedChar('$'));
    assert_eq!(e.span, sp(4, 5));

    let e = err("a # b");
    assert_eq!(e.kind, LexErrorKind::UnexpectedChar('#'));
    assert_eq!(e.span, sp(2, 3));
}

#[test]
fn non_ascii_outside_a_string_is_an_error_with_a_full_width_span() {
    let e = err("é");
    assert_eq!(e.kind, LexErrorKind::UnexpectedChar('é'));
    assert_eq!(e.span, sp(0, 2)); // 2 bytes wide

    let e = err("let 🔥 = 1;");
    assert_eq!(e.kind, LexErrorKind::UnexpectedChar('🔥'));
    assert_eq!(e.span, sp(4, 8)); // 4 bytes wide
}

#[test]
fn first_error_wins() {
    // Both `@` and the unterminated string are wrong; report the first.
    let e = err("@ \"never closed");
    assert_eq!(e.kind, LexErrorKind::UnexpectedChar('@'));
    assert_eq!(e.span, sp(0, 1));
}

// ---------------------------------------------------- 10. whole programs

const EXEC: &str = include_str!("../../../examples/exec.hny");
const EXEC_BURST: &str = include_str!("../../../examples/exec_burst.hny");
const SENSITIVE_OPEN: &str = include_str!("../../../examples/sensitive_open.hny");

#[test]
fn example_exec_starts_as_expected() {
    let k = kinds(EXEC);
    assert_eq!(&k[..3], &[Event, ident("Exec"), LBrace]);
    assert_eq!(k.iter().filter(|k| **k == Probe).count(), 1);
    assert_eq!(k.iter().filter(|k| **k == Emit).count(), 1);
    assert_eq!(*k.last().unwrap(), RBrace);
}

#[test]
fn example_exec_burst_lexes() {
    let k = kinds(EXEC_BURST);
    assert_eq!(&k[..2], &[Const, ident("THRESHOLD")]);
    assert!(k.contains(&Map));
    assert!(k.contains(&Mut));
    assert!(k.contains(&Int(1024)));
    assert!(k.contains(&ident("Some")));
}

#[test]
fn example_sensitive_open_lexes() {
    // This one has a nested block comment, hex + octal literals, a bounded
    // loop, and `return`. If it lexes, most of the lexer works.
    let k = kinds(SENSITIVE_OPEN);
    assert_eq!(&k[..2], &[Const, ident("O_WRONLY")]);
    assert!(k.contains(&Int(0o100)));
    assert!(k.contains(&For));
    assert!(k.contains(&DotDot));
    assert!(k.contains(&Return));
    assert!(k.contains(&string("/etc/shadow")));
}

#[test]
fn every_example_lexes_without_error() {
    for (name, src) in [("exec", EXEC), ("exec_burst", EXEC_BURST), ("sensitive_open", SENSITIVE_OPEN)] {
        if let Err(e) = lex(src) {
            panic!("examples/{name}.hny failed to lex: {e:?}");
        }
    }
}
