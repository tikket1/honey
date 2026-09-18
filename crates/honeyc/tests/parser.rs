//! Stage 2 acceptance tests.
//!
//! Most tests go through the pretty-printer: parse the source, print it,
//! compare strings. The printer parenthesises every compound expression, so
//! `1 + 2 * 3` printing as `(1 + (2 * 3))` proves precedence without
//! building expected ASTs by hand.

use honeyc::ast::*;
use honeyc::parser::{Error, parse, parse_expr};
use honeyc::pretty;
use honeyc::token::Span;

// ---------------------------------------------------------------- helpers

fn e(src: &str) -> String {
    let expr = parse_expr(src).unwrap_or_else(|e| panic!("parse_expr({src:?}) failed: {e:?}"));
    pretty::expr(&expr)
}

fn p(src: &str) -> String {
    let prog = parse(src).unwrap_or_else(|e| panic!("parse({src:?}) failed: {e:?}"));
    pretty::program(&prog)
}

fn parse_err(src: &str) -> Error {
    match parse(src) {
        Ok(prog) => panic!("parse({src:?}) should have failed, got:\n{}", pretty::program(&prog)),
        Err(e) => e,
    }
}

fn sp(start: usize, end: usize) -> Span {
    Span::new(start, end)
}

/// Wrap a statement in a probe so it parses as a program, then return the
/// printed statement lines (without the probe wrapper).
fn stmt(src: &str) -> String {
    let prog = format!("probe t(\"a\") {{ {src} }}");
    let out = p(&prog);
    let body: Vec<&str> = out.lines().skip(1).take_while(|l| *l != "}").collect();
    body.join("\n")
}

// ------------------------------------------------------------ expressions

#[test]
fn literals() {
    assert_eq!(e("42"), "42");
    assert_eq!(e("0xFF"), "255");
    assert_eq!(e("true"), "true");
    assert_eq!(e("false"), "false");
    assert_eq!(e(r#""hi""#), r#""hi""#);
    assert_eq!(e("foo"), "foo");
}

#[test]
fn string_literals_reescape() {
    assert_eq!(e(r#""a\nb\"c\\""#), r#""a\nb\"c\\""#);
}

#[test]
fn arithmetic_precedence() {
    assert_eq!(e("1 + 2 * 3"), "(1 + (2 * 3))");
    assert_eq!(e("1 * 2 + 3"), "((1 * 2) + 3)");
    assert_eq!(e("a - b - c"), "((a - b) - c)");
    assert_eq!(e("a / b % c"), "((a / b) % c)");
}

#[test]
fn parens_override_precedence() {
    assert_eq!(e("(1 + 2) * 3"), "((1 + 2) * 3)");
    assert_eq!(e("((x))"), "x");
}

#[test]
fn logical_precedence() {
    assert_eq!(e("a || b && c"), "(a || (b && c))");
    assert_eq!(e("a && b || c"), "((a && b) || c)");
    assert_eq!(e("!a && b"), "((!a) && b)");
}

#[test]
fn comparison_binds_tighter_than_logical() {
    assert_eq!(e("a == b && c != d"), "((a == b) && (c != d))");
    assert_eq!(e("a < b || c >= d"), "((a < b) || (c >= d))");
}

#[test]
fn bitwise_precedence_matches_rust() {
    // Rust/honey: & tighter than ^ tighter than | tighter than comparison.
    assert_eq!(e("a | b ^ c & d"), "(a | (b ^ (c & d)))");
    assert_eq!(e("a == b & c"), "(a == (b & c))");
    assert_eq!(e("flags & 0x40 != 0"), "((flags & 64) != 0)");
}

#[test]
fn shift_binds_tighter_than_bitwise_looser_than_arithmetic() {
    assert_eq!(e("a << b + c"), "(a << (b + c))");
    assert_eq!(e("a & b << c"), "(a & (b << c))");
    assert_eq!(e("x >> 2"), "(x >> 2)");
}

#[test]
fn unary_operators() {
    assert_eq!(e("-x"), "(-x)");
    assert_eq!(e("!done"), "(!done)");
    assert_eq!(e("~mask"), "(~mask)");
    assert_eq!(e("*p"), "(*p)");
    assert_eq!(e("--x"), "(-(-x))");
    assert_eq!(e("*p + 1"), "((*p) + 1)");
}

#[test]
fn cast_binds_looser_than_unary_tighter_than_binary() {
    assert_eq!(e("-x as u8"), "((-x) as u8)");
    assert_eq!(e("x as u8 + 1"), "((x as u8) + 1)");
    assert_eq!(e("x as u8 as u32"), "((x as u8) as u32)");
}

#[test]
fn calls() {
    assert_eq!(e("pid()"), "pid()");
    assert_eq!(e("f(1, 2)"), "f(1, 2)");
    assert_eq!(e("f(1, 2,)"), "f(1, 2)");
    assert_eq!(e("f(g(x))"), "f(g(x))");
}

#[test]
fn method_calls_fields_and_indexing() {
    assert_eq!(e("m.get(k)"), "m.get(k)");
    assert_eq!(e("s.starts_with(\"/etc\")"), "s.starts_with(\"/etc\")");
    assert_eq!(e("ev.pid"), "ev.pid");
    assert_eq!(e("arr[i]"), "arr[i]");
    assert_eq!(e("a.b(c)[d].e"), "a.b(c)[d].e");
}

#[test]
fn postfix_binds_tighter_than_unary() {
    assert_eq!(e("-f(x)"), "(-f(x))");
    assert_eq!(e("*m.get(k)"), "(*m.get(k))");
}

#[test]
fn expression_spans_cover_the_whole_expression() {
    let ex = parse_expr("1 + 2 * 3").unwrap();
    assert_eq!(ex.span, sp(0, 9));
    let ExprKind::Binary { rhs, .. } = &ex.kind else { panic!() };
    assert_eq!(rhs.span, sp(4, 9));

    let call = parse_expr("m.get(key)").unwrap();
    assert_eq!(call.span, sp(0, 10));
}

// ------------------------------------------------------------------ items

#[test]
fn empty_program() {
    assert_eq!(p(""), "");
    assert_eq!(p("// just a comment"), "");
}

#[test]
fn const_decl() {
    assert_eq!(p("const N: u64 = 100;"), "const N: u64 = 100;\n");
    let prog = parse("const N: u64 = 1 + 2;").unwrap();
    let Item::Const(c) = &prog.items[0] else { panic!() };
    assert_eq!(c.name.name, "N");
    assert_eq!(c.ty.name.name, "u64");
    assert_eq!(c.span, sp(0, 21));
}

#[test]
fn map_decl() {
    assert_eq!(p("map execs: hash<u32, u64>[1024];"), "map execs: hash<u32, u64>[1024];\n");
    let prog = parse("map hits: array<u64>[256];").unwrap();
    let Item::Map(m) = &prog.items[0] else { panic!() };
    assert_eq!(m.kind.name, "array");
    assert_eq!(m.args.len(), 1);
    assert_eq!(m.capacity, 256);
}

#[test]
fn map_decl_with_nested_generics_splits_shr() {
    // The lexer produced `Shr` for `>>`; the parser must split it.
    assert_eq!(p("map names: hash<u32, str<16>>[1024];"), "map names: hash<u32, str<16>>[1024];\n");
    assert_eq!(p("map m: hash<u32, hash<u8, str<4>>>[1];"), "map m: hash<u32, hash<u8, str<4>>>[1];\n");
}

#[test]
fn event_decl() {
    let src = "event Exec { pid: u32, comm: str<16> }";
    assert_eq!(p(src), "event Exec {\n    pid: u32,\n    comm: str<16>,\n}\n");
    // Trailing comma is fine too.
    assert_eq!(p("event E { a: u8, }"), "event E {\n    a: u8,\n}\n");
    assert_eq!(p("event Empty {}"), "event Empty {\n}\n");
}

#[test]
fn probe_decl() {
    let src = r#"probe tracepoint("syscalls", "sys_enter_execve") { }"#;
    assert_eq!(p(src), "probe tracepoint(\"syscalls\", \"sys_enter_execve\") {\n}\n");
    let prog = parse(src).unwrap();
    let Item::Probe(pr) = &prog.items[0] else { panic!() };
    assert_eq!(pr.kind.name, "tracepoint");
    assert_eq!(pr.args, vec!["syscalls", "sys_enter_execve"]);
    assert_eq!(pr.span, sp(0, src.len()));
}

#[test]
fn multiple_items_are_separated_by_blank_lines() {
    let out = p("const A: u8 = 1; const B: u8 = 2;");
    assert_eq!(out, "const A: u8 = 1;\n\nconst B: u8 = 2;\n");
}

// ------------------------------------------------------------- statements

#[test]
fn let_stmt() {
    assert_eq!(stmt("let x = 1;"), "    let x = 1;");
    assert_eq!(stmt("let x: u32 = 1;"), "    let x: u32 = 1;");
    assert_eq!(stmt("let mut n: u64 = 0;"), "    let mut n: u64 = 0;");
    assert_eq!(stmt("let path: str<64> = read_user_str(arg(1));"), "    let path: str<64> = read_user_str(arg(1));");
}

#[test]
fn assign_stmt() {
    assert_eq!(stmt("n = n + 1;"), "    n = (n + 1);");
    assert_eq!(stmt("*p = 0;"), "    (*p) = 0;");
}

#[test]
fn expr_stmt() {
    assert_eq!(stmt("execs.insert(uid, n);"), "    execs.insert(uid, n);");
}

#[test]
fn if_stmt() {
    assert_eq!(stmt("if x { return; }"), "    if x {\n        return;\n    }");
    assert_eq!(stmt("if x { a(); } else { b(); }"), "    if x {\n        a();\n    } else {\n        b();\n    }");
}

#[test]
fn else_if_chain_is_nested_else_blocks() {
    let out = stmt("if a { x(); } else if b { y(); } else { z(); }");
    assert_eq!(
        out,
        "    if a {\n        x();\n    } else {\n        if b {\n            y();\n        } else {\n            z();\n        }\n    }"
    );
}

#[test]
fn if_let_stmt() {
    assert_eq!(
        stmt("if let Some(prev) = execs.get(uid) { n = *prev; }"),
        "    if let Some(prev) = execs.get(uid) {\n        n = (*prev);\n    }"
    );
    assert_eq!(stmt("if let None = m.get(k) { }"), "    if let None = m.get(k) {\n    }");

    let prog = parse("probe t(\"a\") { if let Some(v) = m.get(k) { } }").unwrap();
    let Item::Probe(pr) = &prog.items[0] else { panic!() };
    let StmtKind::If { cond: Cond::Let { pattern, .. }, .. } = &pr.body.stmts[0].kind else { panic!() };
    assert_eq!(pattern.name.name, "Some");
    assert_eq!(pattern.binding.as_ref().unwrap().name, "v");
}

#[test]
fn for_stmt() {
    assert_eq!(stmt("for i in 0..4 { }"), "    for i in 0..4 {\n    }");
    assert_eq!(stmt("for i in a..b + 1 { }"), "    for i in a..(b + 1) {\n    }");
}

#[test]
fn emit_stmt() {
    assert_eq!(stmt("emit Exec { pid: pid(), uid: uid() };"), "    emit Exec { pid: pid(), uid: uid() };");
    assert_eq!(stmt("emit E { a: 1, };"), "    emit E { a: 1 };");
    assert_eq!(stmt("emit E {};"), "    emit E {  };");
}

#[test]
fn return_stmt() {
    assert_eq!(stmt("return;"), "    return;");
    assert_eq!(stmt("return 1 + 2;"), "    return (1 + 2);");
}

#[test]
fn nested_blocks_indent() {
    let out = stmt("for i in 0..2 { if x { return; } }");
    assert_eq!(out, "    for i in 0..2 {\n        if x {\n            return;\n        }\n    }");
}

#[test]
fn statement_spans() {
    let src = "probe t(\"a\") { let x = 1; n = 2; }";
    let prog = parse(src).unwrap();
    let Item::Probe(pr) = &prog.items[0] else { panic!() };
    assert_eq!(pr.body.stmts[0].span, sp(15, 25)); // let x = 1;
    assert_eq!(pr.body.stmts[1].span, sp(26, 32)); // n = 2;
    assert_eq!(pr.body.span, sp(13, 34));
}

// ----------------------------------------------------------------- errors

#[test]
fn missing_semicolon_points_at_the_next_token() {
    let err = parse_err("const N: u64 = 1\nconst M: u64 = 2;");
    let Error::Parse(pe) = err else { panic!("{err:?}") };
    assert!(pe.message.contains("expected `;`"), "{}", pe.message);
    assert!(pe.message.contains("`const`"), "{}", pe.message);
    assert_eq!(pe.span, sp(17, 22));
}

#[test]
fn unknown_item_keyword() {
    let err = parse_err("fn main() {}");
    let Error::Parse(pe) = err else { panic!() };
    assert!(pe.message.contains("expected an item"), "{}", pe.message);
    assert_eq!(pe.span, sp(0, 2));
}

#[test]
fn while_is_rejected_with_a_helpful_message() {
    let err = parse_err("probe t(\"a\") { while true { } }");
    let Error::Parse(pe) = err else { panic!() };
    assert!(pe.message.contains("constant bound"), "{}", pe.message);
    assert_eq!(pe.span, sp(15, 20));
}

#[test]
fn invalid_assignment_target() {
    let err = parse_err("probe t(\"a\") { f() = 1; }");
    let Error::Parse(pe) = err else { panic!() };
    assert!(pe.message.contains("invalid assignment target"), "{}", pe.message);
    assert_eq!(pe.span, sp(15, 18));
}

#[test]
fn unclosed_block() {
    let err = parse_err("probe t(\"a\") { let x = 1;");
    let Error::Parse(pe) = err else { panic!() };
    assert!(pe.message.contains("unclosed block"), "{}", pe.message);
}

#[test]
fn float_literal_is_a_parse_error() {
    let err = parse_err("const X: u64 = 1.5;");
    let Error::Parse(pe) = err else { panic!() };
    // `1` parses, then `.` expects a field name and finds an integer.
    assert!(pe.message.contains("field or method name"), "{}", pe.message);
    assert_eq!(pe.span, sp(17, 18));
}

#[test]
fn lex_errors_propagate() {
    let err = parse_err("const X: u64 = @;");
    assert!(matches!(err, Error::Lex(_)), "{err:?}");
    assert_eq!(err.span(), sp(15, 16));
}

#[test]
fn parse_expr_rejects_trailing_input() {
    assert!(parse_expr("1 2").is_err());
    assert!(parse_expr("").is_err());
}

// --------------------------------------------------------- whole programs

const EXEC: &str = include_str!("../../../examples/exec.hny");
const EXEC_BURST: &str = include_str!("../../../examples/exec_burst.hny");
const SENSITIVE_OPEN: &str = include_str!("../../../examples/sensitive_open.hny");

#[test]
fn every_example_parses() {
    for (name, src) in [("exec", EXEC), ("exec_burst", EXEC_BURST), ("sensitive_open", SENSITIVE_OPEN)] {
        if let Err(e) = parse(src) {
            panic!("examples/{name}.hny failed to parse: {e:?}");
        }
    }
}

#[test]
fn example_exec_structure() {
    let prog = parse(EXEC).unwrap();
    assert_eq!(prog.items.len(), 2);
    assert!(matches!(prog.items[0], Item::Event(_)));
    let Item::Probe(pr) = &prog.items[1] else { panic!() };
    assert_eq!(pr.body.stmts.len(), 1);
    assert!(matches!(pr.body.stmts[0].kind, StmtKind::Emit { .. }));
}

#[test]
fn example_exec_burst_pretty_prints_as_expected() {
    let expected = "\
const THRESHOLD: u64 = 100;

map execs: hash<u32, u64>[1024];

event Burst {
    uid: u32,
    count: u64,
}

probe tracepoint(\"syscalls\", \"sys_enter_execve\") {
    let uid = uid();
    let mut n: u64 = 0;
    if let Some(prev) = execs.get(uid) {
        n = (*prev);
    }
    n = (n + 1);
    execs.insert(uid, n);
    if (n > THRESHOLD) {
        emit Burst { uid: uid, count: n };
    }
}
";
    assert_eq!(p(EXEC_BURST), expected);
}

#[test]
fn pretty_printing_is_a_fixed_point() {
    // parse → print → parse → print must give the same text: the printer
    // emits valid honey and the parser reads its own output.
    for (name, src) in [("exec", EXEC), ("exec_burst", EXEC_BURST), ("sensitive_open", SENSITIVE_OPEN)] {
        let once = p(src);
        let twice = p(&once);
        assert_eq!(once, twice, "examples/{name}.hny is not a fixed point");
    }
}

#[test]
fn field_assignment_target() {
    assert_eq!(stmt("ip.ttl = 7;"), "    ip.ttl = 7;");
    assert_eq!(stmt("a.b.c = d.e;"), "    a.b.c = d.e;");
}
