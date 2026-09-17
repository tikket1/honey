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
    let expected = "
   0: ld64 r1, map_fd(0)
   2: mov r2, 24
   3: mov r3, 0
   4: call 131
   5: if r0 == 0 goto +13
   6: mov r6, r0
   7: call 14
   8: rsh r0, 32
   9: stx32 [r6 +0], r0
  10: call 15
  11: stx32 [r6 +4], r0
  12: mov r1, r6
  13: add r1, 8
  14: mov r2, 16
  15: call 16
  16: mov r1, r6
  17: mov r2, 0
  18: call 132
  19: mov r0, 0
  20: exit
";
    assert_eq!(asm(EXEC), expected.trim_start_matches('\n'));
}

#[test]
fn bytecode_is_a_whole_number_of_instructions() {
    let prog = parse(EXEC).unwrap();
    let c = compile(&prog).unwrap();
    assert_eq!(c.bytecode.len() % 8, 0);
    // 21 instruction slots (the ld_map_fd counts as two 8-byte slots).
    assert_eq!(c.bytecode.len(), 21 * 8);
}

#[test]
fn drop_branch_lands_on_the_final_exit() {
    // The `if r0 == 0 goto +13` at slot 5 must land on `mov r0, 0` (slot 19),
    // just before `exit` (slot 20). +13 from slot 6 = slot 19. This is the
    // one hand-computed offset that would silently corrupt the program if the
    // slot/label arithmetic were wrong.
    let text = asm(EXEC);
    assert!(text.contains("  5: if r0 == 0 goto +13"), "{text}");
    assert!(text.contains("  19: mov r0, 0"), "{text}");
    assert!(text.contains("  20: exit"), "{text}");
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
    // call 15 (uid_gid) then a straight stx32, no rsh in between.
    assert!(text.contains("call 15"), "{text}");
    let after_uid = text.split("call 15").nth(1).unwrap();
    let next_line = after_uid.lines().nth(1).unwrap();
    assert!(next_line.contains("stx32"), "expected stx right after uid call, got: {next_line}");
}

#[test]
fn unsupported_constructs_report_clearly() {
    let cases = [
        ("const X: u64 = 1;", "const"),
        ("map m: hash<u32,u64>[4];", "map"),
    ];
    for (src, needle) in cases {
        let prog = parse(src).unwrap();
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
