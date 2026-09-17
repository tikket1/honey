//! Stage 4 tests: the verifier-aware type checker.
//!
//! The headline check is `every_bad_example_fails_where_it_should`: each
//! file in `examples/bad/` starts with `// error: <text>` and must produce a
//! diagnostic containing that text. Those files are the demo of the whole
//! idea — verifier rejections turned into source-line errors.

use honeyc::parser::parse;
use honeyc::token::Span;
use honeyc::typeck::{check, Diag};

fn diags(src: &str) -> Vec<Diag> {
    let prog = parse(src).unwrap_or_else(|e| panic!("parse failed: {e:?}"));
    match check(&prog) {
        Ok(ok) => panic!("expected type errors, got ok ({} bytes stack)", ok.stack_bytes),
        Err(d) => d,
    }
}

fn ok(src: &str) -> u32 {
    let prog = parse(src).unwrap();
    match check(&prog) {
        Ok(c) => c.stack_bytes,
        Err(d) => panic!("expected ok, got: {:#?}", d),
    }
}

/// Wrap statements in a minimal program with a map, an event, and a probe.
fn probe(body: &str) -> String {
    format!(
        "map m: hash<u32, u64>[8];\nevent E {{ a: u64, b: bool }}\nprobe tracepoint(\"syscalls\", \"sys_enter_execve\") {{\n{body}\n}}"
    )
}

fn first_message(src: &str) -> String {
    diags(src).remove(0).message
}

// ------------------------------------------------------- the bad examples

#[test]
fn every_bad_example_fails_where_it_should() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/bad");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("hny") {
            continue;
        }
        n += 1;
        let src = std::fs::read_to_string(&path).unwrap();
        let expected = src
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("// error: "))
            .unwrap_or_else(|| panic!("{}: first line must be `// error: ...`", path.display()));
        let prog = parse(&src).unwrap_or_else(|e| panic!("{}: parse failed: {e:?}", path.display()));
        let ds = match check(&prog) {
            Ok(_) => panic!("{}: expected a type error, but it passed", path.display()),
            Err(d) => d,
        };
        assert!(
            ds.iter().any(|d| d.message.contains(expected)),
            "{}: expected an error containing {expected:?}, got:\n{:#?}",
            path.display(),
            ds.iter().map(|d| &d.message).collect::<Vec<_>>()
        );
    }
    assert!(n >= 12, "expected the bad examples to exist, found {n}");
}

#[test]
fn every_good_example_passes() {
    for (name, src) in [
        ("exec", include_str!("../../../examples/exec.hny")),
        ("exec_burst", include_str!("../../../examples/exec_burst.hny")),
        ("sensitive_open", include_str!("../../../examples/sensitive_open.hny")),
        ("shadow_open_ok", include_str!("../../../examples/shadow_open_ok.hny")),
    ] {
        let prog = parse(src).unwrap();
        if let Err(d) = check(&prog) {
            panic!("examples/{name}.hny should typecheck, got {d:#?}");
        }
    }
}

#[test]
fn errors_are_reported_together_not_first_only() {
    let src = include_str!("../../../examples/bad/multiple_errors.hny");
    let ds = diags(src);
    let msgs: Vec<&str> = ds.iter().map(|d| d.message.as_str()).collect();
    assert!(msgs.iter().any(|m| m.contains("cannot dereference")), "{msgs:?}");
    assert!(msgs.iter().any(|m| m.contains("unknown name `nope`")), "{msgs:?}");
    assert!(msgs.iter().any(|m| m.contains("expected `bool`")), "{msgs:?}");
    // and no cascade from the unknown name
    assert!(!msgs.iter().any(|m| m.contains("no value to bind")), "{msgs:?}");
}

// --------------------------------------------------- checked map lookups

#[test]
fn deref_of_option_points_at_the_deref_with_a_fix() {
    let src = probe("    let p = m.get(pid());\n    let n = *p;\n    emit E { a: n, b: true };");
    let ds = diags(&src);
    assert_eq!(ds.len(), 1, "{ds:#?}");
    assert!(ds[0].message.contains("cannot dereference `Option<&u64>`"));
    assert!(ds[0].help.as_deref().unwrap().contains("if let Some"));
    // span covers exactly `*p`
    let start = src.find("*p").unwrap();
    assert_eq!(ds[0].span, Span::new(start, start + 2));
}

#[test]
fn if_let_some_gives_a_checked_pointer_in_scope_only() {
    // inside: fine
    ok(&probe("    if let Some(v) = m.get(pid()) { emit E { a: *v, b: true }; }"));
    // outside: not in scope
    let msg = first_message(&probe("    if let Some(v) = m.get(pid()) { }\n    emit E { a: *v, b: true };"));
    assert!(msg.contains("unknown name `v`"), "{msg}");
}

#[test]
fn if_let_none_is_allowed_and_binds_nothing() {
    ok(&probe("    if let None = m.get(pid()) { emit E { a: 1, b: false }; }"));
    let msg = first_message(&probe("    if let None(x) = m.get(pid()) { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("`None` takes no binding"), "{msg}");
}

#[test]
fn if_let_on_a_non_option_is_rejected() {
    let msg = first_message(&probe("    let x = 1;\n    if let Some(v) = x { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("`if let` needs an `Option<&V>`"), "{msg}");
}

#[test]
fn option_cannot_be_stored_where_a_value_is_expected() {
    let ds = diags(&probe("    m.insert(pid(), m.get(pid()));\n    emit E { a: 1, b: true };"));
    assert!(ds[0].message.contains("expected `u64`, found `Option<&u64>`"), "{ds:#?}");
    assert!(ds[0].help.as_deref().unwrap().contains("if let Some"));
}

#[test]
fn map_key_and_value_types_are_enforced() {
    let msg = first_message(&probe("    m.insert(ktime(), 1);\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("expected `u32`, found `u64`"), "{msg}");
    let msg = first_message(&probe("    m.insert(pid(), true);\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("expected `u64`, found `bool`"), "{msg}");
}

#[test]
fn writing_through_a_map_pointer_is_rejected_with_a_hint() {
    let ds = diags(&probe("    if let Some(v) = m.get(pid()) { *v = 3; }\n    emit E { a: 1, b: true };"));
    assert!(ds[0].message.contains("writing through a map pointer"), "{ds:#?}");
    assert!(ds[0].help.as_deref().unwrap().contains("map.insert"));
}

// ----------------------------------------------------------- bounded loops

#[test]
fn loop_bounds_must_be_constants() {
    let ds = diags(&probe("    let n = pid();\n    for i in 0..n { }\n    emit E { a: 1, b: true };"));
    assert!(ds[0].message.contains("`n` is a runtime value, not a constant"), "{ds:#?}");
    assert!(ds[0].help.as_deref().unwrap().contains("bounded"));
}

#[test]
fn loop_bounds_may_be_consts_and_arithmetic() {
    let src = format!("const N: u64 = 4;\n{}", probe("    for i in 0..N + 2 { }\n    emit E { a: 1, b: true };"));
    ok(&src);
}

#[test]
fn loop_limit_and_reversed_range() {
    let msg = first_message(&probe("    for i in 0..65 { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("65 times; the limit is 64"), "{msg}");
    let msg = first_message(&probe("    for i in 5..2 { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("end is before start"), "{msg}");
}

#[test]
fn loop_variable_is_a_constant_usable_as_an_index() {
    let src = "event E { b: u8 }\nprobe tracepoint(\"syscalls\", \"sys_enter_openat\") {\n    let s: str<8> = read_user_str(arg(1));\n    for i in 0..8 { emit E { b: s.byte_at(i) }; }\n}";
    ok(src);
}

// ----------------------------------------------------------- bounded reads

#[test]
fn read_user_str_requires_a_declared_bound() {
    let src = "event E { p: str<16> }\nprobe tracepoint(\"syscalls\", \"sys_enter_openat\") {\n    let p = read_user_str(arg(1));\n    emit E { p: p };\n}";
    let ds = diags(src);
    assert_eq!(ds.len(), 1, "no cascade expected: {ds:#?}");
    assert!(ds[0].message.contains("needs a bounded destination"));
    assert!(ds[0].help.as_deref().unwrap().contains("str<N>"));
}

#[test]
fn string_reads_are_range_checked() {
    let base = "event E { b: u8 }\nprobe tracepoint(\"syscalls\", \"sys_enter_openat\") {\n    let s: str<16> = read_user_str(arg(1));\n";
    ok(&format!("{base}    emit E {{ b: s.byte_at(15) }};\n}}"));
    let msg = first_message(&format!("{base}    emit E {{ b: s.byte_at(16) }};\n}}"));
    assert!(msg.contains("`byte_at(16)` is outside `str<16>`"), "{msg}");
    let msg = first_message(&format!("{base}    let x = s.starts_with(\"/this/prefix/is/too/long\");\n    emit E {{ b: 1 }};\n}}"));
    assert!(msg.contains("prefix is 24 bytes but `s` is only `str<16>`"), "{msg}");
}

#[test]
fn strings_cannot_be_forged_from_literals() {
    let msg = first_message(&probe("    let s = \"hello\";\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("string literals can only be used as `starts_with`"), "{msg}");
}

// ------------------------------------------------------------ stack budget

#[test]
fn stack_usage_is_computed_from_locals() {
    // 24 bytes: uid (8), n (8), prev (8) — see exec_burst.
    let prog = parse(include_str!("../../../examples/exec_burst.hny")).unwrap();
    assert_eq!(check(&prog).unwrap().stack_bytes, 24);
    // 88: path str<64> (64) + flags (8) + hit (8) + write (8)
    let prog = parse(include_str!("../../../examples/sensitive_open.hny")).unwrap();
    assert_eq!(check(&prog).unwrap().stack_bytes, 88);
}

#[test]
fn stack_is_peak_across_sibling_scopes_not_sum() {
    // Two sibling `if` blocks each with a 128-byte string reuse the same
    // stack, so the peak is 128 + the outer local, not 256 + it.
    let src = "event E { b: u8 }\nprobe tracepoint(\"syscalls\", \"sys_enter_openat\") {\n    let x = 1;\n    if x == 1 { let a: str<128> = read_user_str(arg(1)); emit E { b: a.byte_at(0) }; }\n    if x == 2 { let b: str<128> = read_user_str(arg(1)); emit E { b: b.byte_at(0) }; }\n}";
    assert_eq!(ok(src), 136);
}

#[test]
fn stack_overflow_is_a_type_error_with_the_numbers() {
    let src = "event E { b: u8 }\nprobe tracepoint(\"syscalls\", \"sys_enter_openat\") {\n    let a: str<256> = read_user_str(arg(1));\n    let b: str<256> = read_user_str(arg(1));\n    emit E { b: a.byte_at(0) };\n}";
    let ds = diags(src);
    assert!(ds[0].message.contains("512 bytes of stack"), "{ds:#?}");
    assert!(ds[0].message.contains("leaves 472"), "{ds:#?}");
}

// --------------------------------------------------------- ordinary typing

#[test]
fn integer_literals_adapt_but_widths_never_convert() {
    ok(&probe("    let a: u8 = 200;\n    let b = a + 1;\n    emit E { a: 1, b: true };"));
    let msg = first_message(&probe("    let a: u8 = 300;\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("300 does not fit in `u8`"), "{msg}");
    let ds = diags(&probe("    let a: u8 = 1;\n    let c = a + ktime();\n    emit E { a: 1, b: true };"));
    assert!(ds[0].message.contains("mismatched integer widths: `u8` + `u64`"), "{ds:#?}");
}

#[test]
fn conditions_must_be_bool() {
    let msg = first_message(&probe("    if pid() { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("`if` condition must be `bool`, found `u32`"), "{msg}");
    let msg = first_message(&probe("    let x = true && 1;\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("`&&` needs `bool` operands, found `{integer}`"), "{msg}");
}

#[test]
fn immutability_is_enforced() {
    let ds = diags(&probe("    let n = 0;\n    n = 1;\n    emit E { a: n, b: true };"));
    assert!(ds[0].message.contains("cannot assign to `n`: it is not mutable"));
    assert!(ds[0].help.as_deref().unwrap().contains("let mut n"));
    ok(&probe("    let mut n = 0;\n    n = 1;\n    emit E { a: n, b: true };"));
}

#[test]
fn emit_fields_are_checked_completely() {
    let msg = first_message(&probe("    emit E { a: 1 };"));
    assert!(msg.contains("missing field `b`"), "{msg}");
    let msg = first_message(&probe("    emit E { a: 1, b: true, c: 2 };"));
    assert!(msg.contains("has no field `c`"), "{msg}");
    let msg = first_message(&probe("    emit E { a: 1, a: 2, b: true };"));
    assert!(msg.contains("given twice"), "{msg}");
    let msg = first_message(&probe("    emit E { a: true, b: true };"));
    assert!(msg.contains("expected `u64`, found `bool`"), "{msg}");
    let msg = first_message(&probe("    emit Nope { a: 1 };"));
    assert!(msg.contains("unknown event `Nope`"), "{msg}");
}

#[test]
fn comm_only_as_an_emit_field() {
    ok("event X { c: str<16> }\nprobe tracepoint(\"syscalls\", \"sys_enter_execve\") { emit X { c: comm() }; }");
    let msg = first_message(&probe("    let c = comm();\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("`comm()` can only be used directly as an `emit` field"), "{msg}");
    let msg = first_message(&probe("    emit E { a: comm(), b: true };"));
    assert!(msg.contains("`comm()` is a string; field `a` is `u64`"), "{msg}");
}

#[test]
fn builtins_and_args_are_validated() {
    let msg = first_message(&probe("    let x = nonsense();\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("unknown builtin `nonsense`"), "{msg}");
    let msg = first_message(&probe("    let x = pid(1);\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("wrong number of arguments to `pid()`"), "{msg}");
    let msg = first_message(&probe("    let x = arg(6);\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("`arg(6)`: probes expose arguments 0 to 5"), "{msg}");
    ok(&probe("    let x = arg(5);\n    emit E { a: x, b: true };"));
}

#[test]
fn unsupported_v1_constructs_have_hints() {
    let ds = diags(&probe("    let x = pid() as u64;\n    emit E { a: 1, b: true };"));
    assert!(ds[0].message.contains("`as` casts are not supported"), "{ds:#?}");
    assert!(ds[0].help.as_deref().unwrap().contains("let x: u64"));
    let msg = first_message(&probe("    return 1;"));
    assert!(msg.contains("bare `return;`"), "{msg}");
}

#[test]
fn declarations_are_validated() {
    let msg = first_message("map m: tree<u32, u64>[8];\nevent E { a: u64 }\nprobe tracepoint(\"s\", \"n\") { emit E { a: 1 }; }");
    assert!(msg.contains("unknown map kind `tree`"), "{msg}");
    let msg = first_message("event E { a: u64, a: u8 }\nprobe tracepoint(\"s\", \"n\") { emit E { a: 1 }; }");
    assert!(msg.contains("duplicate field `a`"), "{msg}");
    let msg = first_message("const N: u8 = 300;\nevent E { a: u64 }\nprobe tracepoint(\"s\", \"n\") { emit E { a: 1 }; }");
    assert!(msg.contains("300 does not fit in `u8`"), "{msg}");
    let msg = first_message("event E { a: u64 }\nprobe perf(\"cycles\") { emit E { a: 1 }; }");
    assert!(msg.contains("unsupported probe kind `perf`"), "{msg}");
    let msg = first_message("event E { a: u64 }\nprobe kprobe(\"a\", \"b\") { emit E { a: 1 }; }");
    assert!(msg.contains("`kprobe` takes one string argument"), "{msg}");
    let msg = first_message("event E { a: u64 }");
    assert!(msg.contains("program has no `probe`"), "{msg}");
}

// ------------------------------------------------ probe kinds & multi-probe

fn kprobe(body: &str) -> String {
    format!("map m: hash<u32, u8>[8];\nevent E {{ a: u64, r: i64 }}\nprobe kprobe(\"do_sys_openat2\") {{\n{body}\n}}")
}

fn kret(body: &str) -> String {
    format!("map m: hash<u32, u8>[8];\nevent E {{ a: u64, r: i64 }}\nprobe kretprobe(\"do_sys_openat2\") {{\n{body}\n}}")
}

#[test]
fn kprobe_gets_args_but_not_retval() {
    ok(&kprobe("    emit E { a: arg(1), r: 0 };"));
    let ds = diags(&kprobe("    emit E { a: 1, r: retval() };"));
    assert!(ds[0].message.contains("`retval()` is only available in a return probe"), "{ds:#?}");
    assert!(ds[0].help.as_deref().unwrap().contains("kretprobe"));
}

#[test]
fn kretprobe_gets_retval_but_not_args() {
    ok(&kret("    emit E { a: 1, r: retval() };"));
    let ds = diags(&kret("    emit E { a: arg(0), r: retval() };"));
    assert!(ds[0].message.contains("`arg()` is not available in a return probe"), "{ds:#?}");
    assert!(ds[0].help.as_deref().unwrap().contains("tid()"), "{ds:#?}");
}

#[test]
fn retval_is_signed_and_does_not_mix_with_unsigned() {
    // Comparing with a literal is fine; the literal adapts.
    ok(&kret("    let fd = retval();\n    if fd >= 0 { emit E { a: 1, r: fd }; }"));
    // Mixing i64 with u32 is a width/sign error, not a silent conversion.
    let ds = diags(&kret("    let x = retval() + uid();\n    emit E { a: 1, r: 0 };"));
    assert!(ds[0].message.contains("mismatched integer widths: `i64` + `u32`"), "{ds:#?}");
    // And an i64 cannot be stored in a u64 field.
    let ds = diags(&kret("    emit E { a: retval(), r: 0 };"));
    assert!(ds[0].message.contains("expected `u64`, found `i64`"), "{ds:#?}");
}

#[test]
fn tracepoint_has_no_retval() {
    let msg = first_message(&probe("    let r = retval();\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("only available in a return probe"), "{msg}");
}

#[test]
fn multiple_probes_each_get_their_own_stack_budget() {
    // Two probes with 400-byte strings each: fine, because each BPF program
    // has its own 512-byte stack. One probe with both: over budget.
    let two = "event E { b: u8 }\nprobe kprobe(\"f\") { let a: str<256> = read_user_str(arg(0)); emit E { b: a.byte_at(0) }; }\nprobe kretprobe(\"f\") { let r = retval(); if r >= 0 { emit E { b: 1 }; } }";
    assert_eq!(ok(two), 256);
    let one = "event E { b: u8 }\nprobe kprobe(\"f\") { let a: str<256> = read_user_str(arg(0)); let c: str<256> = read_user_str(arg(1)); emit E { b: a.byte_at(0) }; }";
    let ds = diags(one);
    assert!(ds[0].message.contains("512 bytes of stack"), "{ds:#?}");
}

#[test]
fn probes_can_emit_different_events() {
    ok("event A { x: u64 }\nevent B { y: u32 }\nprobe kprobe(\"f\") { emit A { x: arg(0) }; }\nprobe kretprobe(\"f\") { emit B { y: uid() }; }");
}

// ------------------------------------------------------------- lsm probes

#[test]
fn lsm_allows_deny_and_allow() {
    ok("event E { u: u32 } probe lsm(\"file_open\") { if uid() == 0 { emit E { u: uid() }; deny(); } }");
    ok("event E { u: u32 } probe lsm(\"file_open\") { allow(); }");
}

#[test]
fn deny_and_allow_are_lsm_only() {
    let msg = first_message(&probe("    deny();\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("`deny()` is only available in an `lsm` probe"), "{msg}");
    let msg = first_message("event E { a: u64 } probe kprobe(\"f\") { allow(); emit E { a: 1 }; }");
    assert!(msg.contains("`allow()` is only available in an `lsm` probe"), "{msg}");
}

#[test]
fn lsm_takes_one_hook_argument() {
    let msg = first_message("event E { a: u64 } probe lsm(\"a\", \"b\") { emit E { a: 1 }; }");
    assert!(msg.contains("`lsm` takes one string argument"), "{msg}");
}

#[test]
fn lsm_has_args_but_no_retval() {
    ok("event E { a: u64 } probe lsm(\"file_open\") { emit E { a: arg(0) }; }");
    let msg = first_message("event E { a: u64, r: i64 } probe lsm(\"file_open\") { emit E { a: 1, r: retval() }; }");
    assert!(msg.contains("`retval()` is only available in a return probe"), "{msg}");
}

// -------------------------------------------------------------- xdp probes

fn xdp(body: &str) -> String {
    format!("event E {{ a: u32, b: u16 }}\nprobe xdp(\"lo\") {{\n{body}\n}}")
}

#[test]
fn xdp_packet_reads_have_fixed_widths() {
    ok(&xdp("    emit E { a: pkt.u32(26), b: pkt.u16(12) };"));
    let msg = first_message(&xdp("    emit E { a: pkt.u16(12), b: 0 };"));
    assert!(msg.contains("expected `u32`, found `u16`"), "{msg}");
    ok(&xdp("    let n: u32 = pkt.len();\n    emit E { a: n, b: 0 };"));
}

#[test]
fn xdp_actions_and_their_scope() {
    ok(&xdp("    if pkt.u8(23) == 1 { drop(); }\n    pass();"));
    let msg = first_message(&probe("    drop();\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("`drop()` is only available in an `xdp` probe"), "{msg}");
    let msg = first_message(&xdp("    deny();"));
    assert!(msg.contains("`deny()` is only available in an `lsm` probe"), "{msg}");
}

#[test]
fn xdp_has_no_process_context() {
    let msg = first_message(&xdp("    emit E { a: pid(), b: 0 };"));
    assert!(msg.contains("`pid()` is not available in an `xdp` probe"), "{msg}");
    let msg = first_message(&xdp("    let x = arg(0);\n    emit E { a: 1, b: 0 };"));
    assert!(msg.contains("`arg()` is not available in an `xdp` probe"), "{msg}");
}

#[test]
fn pkt_only_in_xdp_and_offsets_are_constants() {
    let msg = first_message(&probe("    emit E { a: 1, b: pkt.u8(0) == 1 };"));
    assert!(msg.contains("`pkt` is only available in an `xdp` probe"), "{msg}");
    let ds = diags(&xdp("    let i = 4;\n    emit E { a: 1, b: pkt.u16(i) };"));
    assert!(ds[0].message.contains("packet offset `i` is a variable"), "{ds:#?}");
    let msg = first_message(&xdp("    emit E { a: pkt.u32(300), b: 0 };"));
    assert!(msg.contains("ends past 256 bytes"), "{msg}");
    // consts are fine
    ok(&format!("const IP_PROTO: u64 = 23;\n{}", xdp("    if pkt.u8(IP_PROTO) == 6 { drop(); }")));
}

// ------------------------------------------------------- uprobes & sampling

#[test]
fn uprobe_target_must_be_path_and_symbol() {
    ok("event E { p: u32 } probe uprobe(\"/lib/libc.so.6:getenv\") { emit E { p: pid() }; }");
    let msg = first_message("event E { p: u32 } probe uprobe(\"getenv\") { emit E { p: pid() }; }");
    assert!(msg.contains("uprobe target must be `path:symbol`"), "{msg}");
}

#[test]
fn uprobe_has_args_and_process_context() {
    // arg + read_user_str + pid all work at a uprobe.
    ok("event E { p: u32, n: str<16> } probe uprobe(\"/l:getenv\") { let n: str<16> = read_user_str(arg(0)); emit E { p: pid(), n: n }; }");
    // retval does not, at entry.
    let msg = first_message("event E { r: i64 } probe uprobe(\"/l:getenv\") { emit E { r: retval() }; }");
    assert!(msg.contains("only available in a return probe"), "{msg}");
}

#[test]
fn uretprobe_has_retval_but_not_args() {
    ok("event E { r: i64 } probe uretprobe(\"/l:getenv\") { emit E { r: retval() }; }");
    let msg = first_message("event E { p: u64 } probe uretprobe(\"/l:getenv\") { emit E { p: arg(0) }; }");
    assert!(msg.contains("not available in a return probe"), "{msg}");
}

#[test]
fn sample_returns_bool_with_a_positive_rate() {
    ok(&probe("    if sample(100) { emit E { a: 1, b: true }; }"));
    ok(&probe("    let x = sample(1000);\n    emit E { a: 1, b: x };"));
    let msg = first_message(&probe("    if sample(0) { emit E { a: 1, b: true }; }"));
    assert!(msg.contains("the rate must be at least 1"), "{msg}");
    let msg = first_message(&probe("    if sample(x) { emit E { a: 1, b: true }; }"));
    assert!(msg.contains("unknown name `x`") || msg.contains("constant"), "{msg}");
}

#[test]
fn sample_works_in_any_probe_kind() {
    ok("event E { t: u16 } probe xdp(\"lo\") { if sample(10) { emit E { t: pkt.u16(12) }; } }");
}

// ---------------------------------------------------------- string equality

fn with_path(body: &str) -> String {
    format!("event E {{ a: u32, b: bool }}\nprobe tracepoint(\"syscalls\", \"sys_enter_execve\") {{\n    let path: str<32> = read_user_str(arg(0));\n    let other: str<16> = read_user_str(arg(0));\n{body}\n}}")
}

#[test]
fn string_equality_with_a_literal_and_between_locals() {
    ok(&with_path("    if path == \"/bin/sh\" { emit E { a: 1, b: true }; }"));
    ok(&with_path("    let same = path != \"/bin/sh\";\n    emit E { a: 1, b: same };"));
    ok(&with_path("    if path == other { emit E { a: 1, b: path != other }; }"));
}

#[test]
fn string_literal_longer_than_capacity_can_never_match() {
    let ds = diags(&with_path("    if other == \"/usr/local/bin/something\" { }\n    emit E { a: 1, b: true };"));
    assert!(ds[0].message.contains("can never be equal"), "{ds:#?}");
    assert!(ds[0].help.as_deref().unwrap().contains("enlarge"));
    // exactly the capacity is fine (no room for a NUL is allowed)
    ok(&with_path("    if other == \"0123456789abcdef\" { }\n    emit E { a: 1, b: true };"));
}

#[test]
fn strings_only_support_equality() {
    let msg = first_message(&with_path("    if path < \"/bin\" { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("strings and addresses do not support `<`"), "{msg}");
}

#[test]
fn string_vs_non_string_is_an_error() {
    let msg = first_message(&with_path("    if path == 5 { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("cannot compare `str<32>` with `{integer}`"), "{msg}");
    // a u32 only accepts a dotted-quad literal
    let msg = first_message(&with_path("    if pid() == \"x\" { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("is not an IPv4 address literal"), "{msg}");
    let msg = first_message(&with_path("    if ktime() == \"x\" { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("cannot compare a string literal with `u64`"), "{msg}");
    let msg = first_message(&with_path("    if \"a\" == \"a\" { }\n    emit E { a: 1, b: true };"));
    assert!(msg.contains("two string literals"), "{msg}");
}

// ------------------------------------------------------------ usdt & ipv4

#[test]
fn usdt_target_shape_and_context() {
    ok("event E { p: u32, c: str<16> } probe usdt(\"/usr/bin/python3:python:function__entry\") { emit E { p: pid(), c: comm() }; }");
    let msg = first_message("event E { p: u32 } probe usdt(\"/usr/bin/python3:function__entry\") { emit E { p: pid() }; }");
    assert!(msg.contains("usdt target must be `path:provider:name`"), "{msg}");
    // arguments come from the marker's note, via a runtime spec
    ok("event E { a: u64, s: str<16> } probe usdt(\"/b:p:n\") { let s: str<16> = read_user_str(arg(1)); emit E { a: arg(0), s: s }; }");
    let msg = first_message("event E { a: u64 } probe usdt(\"/b:p:n\") { emit E { a: arg(6) }; }");
    assert!(msg.contains("arguments 0 to 5"), "{msg}");
    ok("event E { p: u32 } probe usdt(\"/b:p:n\") { if sample(10) { emit E { p: pid() }; } }");
}

#[test]
fn ipv4_is_a_u32_to_the_type_system() {
    // pkt.u32 (u32) fits an ipv4 field; a u16 does not; a literal adapts.
    ok("event E { src: ipv4 } probe xdp(\"lo\") { emit E { src: pkt.u32(26) }; }");
    ok("event E { src: ipv4 } probe xdp(\"lo\") { emit E { src: 2130706433 }; }");
    let msg = first_message("event E { src: ipv4 } probe xdp(\"lo\") { emit E { src: pkt.u16(12) }; }");
    assert!(msg.contains("expected `u32`, found `u16`"), "{msg}");
    // usable as a map value and a local type too
    ok("map seen: hash<u32, ipv4>[8]\nevent E { a: u32 } probe xdp(\"lo\") { let ip: ipv4 = pkt.u32(26); seen.insert(1, ip); emit E { a: 1 }; }".replace("[8]\n", "[8];\n").as_str());
}

// ------------------------------------------------------------ ipv6 & mac

#[test]
fn ipv6_and_mac_are_packet_blobs() {
    ok("event E { s: ipv6, m: mac } probe xdp(\"lo\") { emit E { s: pkt.ipv6(22), m: pkt.mac(6) }; }");
    ok("event E { s: ipv6 } probe xdp(\"lo\") { let a = pkt.ipv6(22); emit E { s: a }; }");
    ok("event E { s: ipv6 } probe xdp(\"lo\") { let a: ipv6 = pkt.ipv6(22); emit E { s: a }; }");
    // wrong blob kind for the field
    let msg = first_message("event E { s: ipv6 } probe xdp(\"lo\") { emit E { s: pkt.mac(6) }; }");
    assert!(msg.contains("expected `ipv6`, found `mac`"), "{msg}");
}

#[test]
fn blobs_only_come_from_the_packet_and_cannot_be_compared_or_reassigned() {
    let msg = first_message("event E { s: ipv6 } probe xdp(\"lo\") { let x: ipv6 = 5; emit E { s: x }; }");
    assert!(msg.contains("an `ipv6` value can only come straight from the packet") || msg.contains("expected `ipv6`"), "{msg}");
    // same-kind addresses compare; `<` on them does not
    ok("event E { a: u8 } probe xdp(\"lo\") { let a = pkt.ipv6(22); let b = pkt.ipv6(38); if a == b { emit E { a: 1 }; } }");
    let msg = first_message("event E { a: u8 } probe xdp(\"lo\") { let a = pkt.ipv6(22); let b = pkt.ipv6(38); if a < b { emit E { a: 1 }; } }");
    assert!(msg.contains("do not support `<`"), "{msg}");
    let msg = first_message("event E { a: u8 } probe xdp(\"lo\") { let mut a = pkt.mac(0); a = pkt.mac(6); emit E { a: 1 }; }");
    assert!(msg.contains("is a `mac` buffer and cannot be reassigned"), "{msg}");
    // not in a map, not in a kprobe
    let msg = first_message("map m: hash<u32, ipv6>[4];\nevent E { a: u8 } probe xdp(\"lo\") { emit E { a: 1 }; }");
    assert!(msg.contains("map keys and values must be integers or bool"), "{msg}");
}

#[test]
fn blob_reads_count_toward_the_packet_bound() {
    let msg = first_message("event E { s: ipv6 } probe xdp(\"lo\") { emit E { s: pkt.ipv6(250) }; }");
    assert!(msg.contains("ends past 256 bytes"), "{msg}");
    ok("event E { s: ipv6 } probe xdp(\"lo\") { emit E { s: pkt.ipv6(240) }; }");
}

// ------------------------------------------------------ address comparison

#[test]
fn addresses_compare_with_literals_and_each_other() {
    ok("event E { a: u8 } probe xdp(\"lo\") { let s = pkt.ipv6(22); if s == \"::1\" || s != \"fe80::1\" { emit E { a: 1 }; } }");
    ok("event E { a: u8 } probe xdp(\"lo\") { let m = pkt.mac(6); if m == \"aa:bb:cc:dd:ee:ff\" { emit E { a: 1 }; } }");
    ok("event E { a: u8 } probe xdp(\"lo\") { let a = pkt.mac(0); let b = pkt.mac(6); emit E { a: 1 }; if a != b { emit E { a: 2 }; } }");
    ok("event E { a: u8 } probe xdp(\"lo\") { if pkt.u32(26) == \"127.0.0.1\" { emit E { a: 1 }; } }");
    ok("event E { a: u8 } probe xdp(\"lo\") { let ip: ipv4 = pkt.u32(30); if \"10.0.0.1\" != ip { emit E { a: 1 }; } }");
}

#[test]
fn address_literals_are_validated_and_kinds_must_match() {
    let msg = first_message("event E { a: u8 } probe xdp(\"lo\") { let s = pkt.ipv6(22); if s == \"1::2::3\" { emit E { a: 1 }; } }");
    assert!(msg.contains("is not a valid `ipv6` literal"), "{msg}");
    let msg = first_message("event E { a: u8 } probe xdp(\"lo\") { let m = pkt.mac(6); if m == \"::1\" { emit E { a: 1 }; } }");
    assert!(msg.contains("is not a valid `mac` literal"), "{msg}");
    let msg = first_message("event E { a: u8 } probe xdp(\"lo\") { let s = pkt.ipv6(22); let m = pkt.mac(6); if s == m { emit E { a: 1 }; } }");
    assert!(msg.contains("cannot compare `ipv6` with `mac`"), "{msg}");
    let msg = first_message("event E { a: u8 } probe xdp(\"lo\") { if pkt.u32(26) == \"1.2.3\" { emit E { a: 1 }; } }");
    assert!(msg.contains("is not an IPv4 address literal"), "{msg}");
}
