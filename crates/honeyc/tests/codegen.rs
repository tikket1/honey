//! Stage 3 codegen tests (Mac-side).
//!
//! These check the *shape* of the emitted bytecode via the disassembler and
//! the computed event layout. They do not load anything into a kernel; that
//! is the loader's job and lives in `linux/`. The kernel verifier is the
//! ultimate check, but these catch regressions without needing Linux.

use honeyc::codegen::compile;
use honeyc::layout::{layout_event, FieldKind};
use honeyc::parser::parse;
use honeyc::ast::Item;

fn asm(src: &str) -> String {
    let prog = parse(src).unwrap();
    let c = compile(&prog).unwrap_or_else(|e| panic!("codegen failed: {e}"));
    // Re-decode and disassemble, mirroring `honeyc --asm`.
    disasm_bytes(&c.bytecode)
}

fn disasm_bytes(bytes: &[u8]) -> String {
    let mut insns = Vec::new();
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let opcode = bytes[i];
        let dst = bytes[i + 1] & 0x0f;
        let src = bytes[i + 1] >> 4;
        let off = i16::from_le_bytes([bytes[i + 2], bytes[i + 3]]);
        let imm = i32::from_le_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]);
        if opcode == 0x18 {
            let hi = i32::from_le_bytes([bytes[i + 12], bytes[i + 13], bytes[i + 14], bytes[i + 15]]);
            insns.push(honeyc::bpf::Insn::from_parts(opcode, dst, src, off, imm, Some(hi)));
            i += 16;
        } else {
            insns.push(honeyc::bpf::Insn::from_parts(opcode, dst, src, off, imm, None));
            i += 8;
        }
    }
    honeyc::bpf::disasm_prog(&insns)
}

const EXEC: &str = include_str!("../../../examples/exec.hny");

#[test]
fn exec_compiles_to_the_expected_program() {
    let expected = "\n   0: stx64 [r10 -8], r1
   1: ld64 r1, map_fd(0)
   3: mov r2, 24
   4: mov r3, 0
   5: call 131
   6: if r0 == 0 goto +14
   7: mov r6, r0
   8: call 14
   9: rsh r0, 32
  10: stx32 [r6 +0], r0
  11: call 15
  12: mov32 r0, r0
  13: stx32 [r6 +4], r0
  14: mov r1, r6
  15: add r1, 8
  16: mov r2, 16
  17: call 16
  18: mov r1, r6
  19: mov r2, 0
  20: call 132
  21: mov r0, 0
  22: exit
";
    assert_eq!(asm(EXEC), expected.trim_start_matches('\n'));
}

#[test]
fn bytecode_is_a_whole_number_of_instructions() {
    let prog = parse(EXEC).unwrap();
    let c = compile(&prog).unwrap();
    assert_eq!(c.bytecode.len() % 8, 0);
    // 23 instruction slots (the ld_map_fd counts as two 8-byte slots).
    assert_eq!(c.bytecode.len(), 23 * 8);
}

#[test]
fn drop_branch_lands_on_the_final_exit() {
    // The reserve-failed jump must skip the whole emit and land on the
    // final `mov r0, 0` right before `exit`. If slot/label arithmetic were
    // off by one this would silently run a helper with a null pointer.
    let text = asm(EXEC);
    assert!(text.contains("6: if r0 == 0 goto +14"), "{text}");
    assert!(text.contains("21: mov r0, 0"), "{text}");
    assert!(text.contains("22: exit"), "{text}");
}

#[test]
fn event_layout_aligns_and_pads() {
    let prog = parse("event E { a: u8, b: u32, c: str<3> }").unwrap();
    let Item::Event(ev) = &prog.items[0] else { panic!() };
    let l = layout_event(ev).unwrap();
    // a@0 (1 byte), b needs 4-align so @4, c@8, total 11 rounded up to 12.
    assert_eq!(l.fields[0].offset, 0);
    assert_eq!(l.fields[1].offset, 4);
    assert_eq!(l.fields[2].offset, 8);
    assert_eq!(l.size, 12);
    assert_eq!(l.fields[2].kind, FieldKind::Str(3));
}

#[test]
fn uid_field_high_half_is_not_shifted() {
    // uid() stores the low 32 bits directly (no rsh), unlike pid().
    let src = "event U { uid: u32 } probe tracepoint(\"syscalls\",\"sys_enter_execve\") { emit U { uid: uid() }; }";
    let text = asm(src);
    // call 15 (uid_gid), zero-extend the low 32 bits, then store. No rsh.
    assert!(text.contains("call 15"), "{text}");
    let after_uid = text.split("call 15").nth(1).unwrap();
    let l1 = after_uid.lines().nth(1).unwrap();
    let l2 = after_uid.lines().nth(2).unwrap();
    assert!(l1.contains("mov32 r0, r0"), "expected zero-extend after uid call, got: {l1}");
    assert!(l2.contains("stx32"), "expected store after zero-extend, got: {l2}");
    assert!(!after_uid.contains("rsh r0, 32"), "uid must not be shifted");
}

#[test]
fn unsupported_constructs_report_clearly() {
    let probe = |body: &str| format!("event E {{ a: u32 }} probe tracepoint(\"s\",\"n\") {{ {body} emit E {{ a: pid() }}; }}");
    let cases = [
        (probe("let x = 1 as u8;"), "as"),
        (probe("return 7;"), "return"),
        ("event E { a: u32 }".to_string(), "no probe"),
    ];
    for (src, needle) in cases {
        let prog = parse(&src).unwrap();
        let err = compile(&prog).unwrap_err();
        assert!(err.contains(needle), "error {err:?} should mention {needle:?}");
    }
}

#[test]
fn wrong_field_count_is_rejected() {
    let src = "event E { a: u32, b: u32 } probe tracepoint(\"s\",\"n\") { emit E { a: pid() }; }";
    let prog = parse(src).unwrap();
    assert!(compile(&prog).unwrap_err().contains("fields"));
}

// ------------------------------------------------------- stage 3b: maps

const EXEC_BURST: &str = include_str!("../../../examples/exec_burst.hny");

#[test]
fn exec_burst_compiles() {
    let prog = parse(EXEC_BURST).unwrap();
    let c = compile(&prog).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.maps.len(), 1);
    assert_eq!(c.maps[0].name, "execs");
    assert_eq!(c.maps[0].kind, honeyc::codegen::MapKind::Hash);
    assert_eq!((c.maps[0].key_size, c.maps[0].value_size, c.maps[0].max_entries), (4, 8, 1024));
    assert_eq!(c.event.name, "Burst");
    assert_eq!(c.event.size, 16);
    assert!(c.stack_bytes <= 512);
}

#[test]
fn map_lookup_spills_then_null_checks() {
    // The verifier needs: lookup result checked for null before any deref.
    // Our shape: call 1, spill r0, `if r0 == 0`, and only then reload+deref.
    let text = asm(EXEC_BURST);
    let after = text.split("call 1\n").nth(1).unwrap();
    let l: Vec<&str> = after.lines().take(4).collect();
    assert!(l[0].contains("stx64 [r10"), "{l:?}");
    assert!(l[1].contains("if r0 == 0 goto"), "{l:?}");
    assert!(l[2].contains("ldx64 r0, [r10"), "{l:?}");
    assert!(l[3].contains("ldx64 r0, [r0 +0]"), "{l:?}");
}

#[test]
fn map_insert_passes_key_and_value_pointers() {
    let text = asm(EXEC_BURST);
    let lines: Vec<&str> = text.lines().collect();
    let at = lines.iter().position(|l| l.ends_with(" call 2")).expect("map_update_elem call");
    // The six instructions before the call set up: r1 = map, r2 = &key,
    // r3 = &value, r4 = 0 (BPF_ANY).
    let setup = &lines[at - 6..at];
    assert!(setup[0].contains("ld64 r1, map_fd(1)"), "{setup:?}");
    assert!(setup[1].contains("mov r2, r10"), "{setup:?}");
    assert!(setup[2].contains("add r2, -"), "{setup:?}");
    assert!(setup[3].contains("mov r3, r10"), "{setup:?}");
    assert!(setup[4].contains("add r3, -"), "{setup:?}");
    assert!(setup[5].contains("mov r4, 0"), "{setup:?}");
}

#[test]
fn threshold_compare_guards_the_emit() {
    let text = asm(EXEC_BURST);
    // `if n > THRESHOLD` becomes: r0 = 100, r1 = n, `if r1 > r0 goto then; goto else`
    assert!(text.contains("mov r0, 100"), "{text}");
    assert!(text.contains("if r1 > r0 goto +1"), "{text}");
}

#[test]
fn deref_before_null_check_is_rejected() {
    let src = "map m: hash<u32,u64>[4]; event E { a: u64 } probe tracepoint(\"s\",\"n\") { let p = m.get(1); emit E { a: *p }; }";
    let prog = parse(src).unwrap();
    let err = compile(&prog).unwrap_err();
    assert!(err.contains("if let Some"), "{err}");
}

#[test]
fn stack_usage_is_tracked() {
    // exec_burst: uid, n, prev/temps. Small, but nonzero and 8-aligned.
    let prog = parse(EXEC_BURST).unwrap();
    let c = compile(&prog).unwrap();
    assert!(c.stack_bytes >= 24 && c.stack_bytes.is_multiple_of(8), "{}", c.stack_bytes);
}

// ------------------------------------------------ stage 3c: strings + for

const SENSITIVE: &str = include_str!("../../../examples/sensitive_open.hny");

#[test]
fn sensitive_open_compiles() {
    let prog = parse(SENSITIVE).unwrap();
    let c = compile(&prog).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.event.name, "SensitiveOpen");
    // path is a str<64> field.
    let path = c.event.fields.iter().find(|f| f.name == "path").unwrap();
    assert_eq!(path.size, 64);
    assert!(c.stack_bytes <= 512, "stack {}", c.stack_bytes);
}

#[test]
fn context_pointer_is_saved_at_entry() {
    // First instruction must spill R1 (the ctx) so arg(n) can read it later.
    let text = asm(SENSITIVE);
    assert!(text.starts_with("   0: stx64 [r10 -8], r1"), "{}", &text[..40]);
}

#[test]
fn arg_reads_context_at_the_right_offset() {
    // arg(1) on openat -> load ctx, then ldx [ctx + 24].
    let text = asm(SENSITIVE);
    assert!(text.contains("ldx64 r0, [r0 +24]"), "arg(1) should read ctx+24\n{text}");
}

#[test]
fn starts_with_is_unrolled_byte_compares() {
    // "/etc/shadow" is 11 bytes -> 11 byte loads guarding the prefix. Check
    // the first two bytes: '/' = 47, 'e' = 101.
    let text = asm(SENSITIVE);
    assert!(text.contains("if r0 != 47 goto"), "{text}");
    assert!(text.contains("if r0 != 101 goto"), "{text}");
}

#[test]
fn for_loop_is_fully_unrolled() {
    // `for i in 0..4 { if path.byte_at(i) == 0 { return; } }` unrolls to four
    // byte loads at offsets 0..3 from the path buffer. There must be no
    // backward jump (no loop) in the program.
    let text = asm(SENSITIVE);
    for line in text.lines() {
        if let Some(rest) = line.split("goto ").nth(1) {
            let off: i64 = rest.trim().trim_start_matches('+').parse().unwrap_or(0);
            assert!(off >= 0, "unexpected backward jump (a real loop): {line}");
        }
    }
}

#[test]
fn for_bounds_must_be_constant() {
    let src = "event E { a: u32 } probe tracepoint(\"s\",\"n\") { let n = pid(); for i in 0..n { } emit E { a: pid() }; }";
    let prog = parse(src).unwrap();
    let err = compile(&prog).unwrap_err();
    assert!(err.contains("constant"), "{err}");
}

#[test]
fn every_example_compiles_and_verifies_shape() {
    for (name, src) in [("exec", EXEC), ("exec_burst", EXEC_BURST), ("sensitive_open", SENSITIVE)] {
        let prog = parse(src).unwrap();
        let c = compile(&prog).unwrap_or_else(|e| panic!("{name} failed: {e}"));
        assert_eq!(c.bytecode.len() % 8, 0, "{name}");
        assert!(c.stack_bytes <= 512, "{name} stack {}", c.stack_bytes);
    }
}
