//! Stage 3 codegen tests (Mac-side).
//!
//! These check the *shape* of the emitted bytecode via the disassembler and
//! the computed event layout. They do not load anything into a kernel; that
//! is the loader's job and lives in `linux/`. The kernel verifier is the
//! ultimate check, but these catch regressions without needing Linux.

use honeyc::codegen::{compile, Arch};
use honeyc::layout::{layout_event, FieldKind};
use honeyc::parser::parse;
use honeyc::ast::Item;

fn asm(src: &str) -> String {
    let prog = parse(src).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap_or_else(|e| panic!("codegen failed: {e}"));
    // Re-decode and disassemble the first program, mirroring `honeyc --asm`.
    disasm_bytes(&c.programs[0].bytecode)
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
   3: mov r2, 32
   4: mov r3, 0
   5: call 131
   6: if r0 == 0 goto +16
   7: mov r6, r0
   8: st32 [r6 +0], 0
   9: st32 [r6 +4], 0
  10: call 14
  11: rsh r0, 32
  12: stx32 [r6 +8], r0
  13: call 15
  14: mov32 r0, r0
  15: stx32 [r6 +12], r0
  16: mov r1, r6
  17: add r1, 16
  18: mov r2, 16
  19: call 16
  20: mov r1, r6
  21: mov r2, 0
  22: call 132
  23: mov r0, 0
  24: exit
";
    assert_eq!(asm(EXEC), expected.trim_start_matches('\n'));
}

#[test]
fn bytecode_is_a_whole_number_of_instructions() {
    let prog = parse(EXEC).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    let code = &c.programs[0].bytecode;
    assert_eq!(code.len() % 8, 0);
    // 25 instruction slots (the ld_map_fd counts as two 8-byte slots).
    assert_eq!(code.len(), 25 * 8);
}

#[test]
fn drop_branch_lands_on_the_final_exit() {
    // The reserve-failed jump must skip the whole emit and land on the
    // final `mov r0, 0` right before `exit`. If slot/label arithmetic were
    // off by one this would silently run a helper with a null pointer.
    let text = asm(EXEC);
    assert!(text.contains("6: if r0 == 0 goto +16"), "{text}");
    assert!(text.contains("23: mov r0, 0"), "{text}");
    assert!(text.contains("24: exit"), "{text}");
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
        let err = compile(&prog, Arch::Aarch64).unwrap_err();
        assert!(err.contains(needle), "error {err:?} should mention {needle:?}");
    }
}

// ------------------------------------------------------- stage 3b: maps

const EXEC_BURST: &str = include_str!("../../../examples/exec_burst.hny");

#[test]
fn exec_burst_compiles() {
    let prog = parse(EXEC_BURST).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.maps.len(), 1);
    assert_eq!(c.maps[0].name, "execs");
    assert_eq!(c.maps[0].kind, honeyc::codegen::MapKind::Hash);
    assert_eq!((c.maps[0].key_size, c.maps[0].value_size, c.maps[0].max_entries), (4, 8, 1024));
    assert_eq!(c.events[0].name, "Burst");
    assert_eq!(c.events[0].size, 16);
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
fn codegen_still_refuses_an_unchecked_deref() {
    // The type checker is the gate (see tests/typeck.rs); codegen keeps a
    // backstop so it can never emit a deref of a map_value_or_null pointer.
    let src = "map m: hash<u32,u64>[4]; event E { a: u64 } probe tracepoint(\"s\",\"n\") { let p = m.get(1); emit E { a: *p }; }";
    let prog = parse(src).unwrap();
    let err = compile(&prog, Arch::Aarch64).unwrap_err();
    assert!(err.contains("unchecked"), "{err}");
}

#[test]
fn stack_usage_is_tracked() {
    // exec_burst: uid, n, prev/temps. Small, but nonzero and 8-aligned.
    let prog = parse(EXEC_BURST).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert!(c.stack_bytes >= 24 && c.stack_bytes.is_multiple_of(8), "{}", c.stack_bytes);
}

// ------------------------------------------------ stage 3c: strings + for

const SENSITIVE: &str = include_str!("../../../examples/sensitive_open.hny");

#[test]
fn sensitive_open_compiles() {
    let prog = parse(SENSITIVE).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.events[0].name, "SensitiveOpen");
    // path is a str<64> field.
    let path = c.events[0].fields.iter().find(|f| f.name == "path").unwrap();
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
    let err = compile(&prog, Arch::Aarch64).unwrap_err();
    assert!(err.contains("constant"), "{err}");
}

#[test]
fn every_example_compiles_and_verifies_shape() {
    for (name, src) in [("exec", EXEC), ("exec_burst", EXEC_BURST), ("sensitive_open", SENSITIVE), ("shadow_open_ok", SHADOW)] {
        let prog = parse(src).unwrap();
        let c = compile(&prog, Arch::Aarch64).unwrap_or_else(|e| panic!("{name} failed: {e}"));
        for p in &c.programs {
            assert_eq!(p.bytecode.len() % 8, 0, "{name}/{}", p.name);
            assert!(p.stack_bytes <= 512, "{name}/{} stack {}", p.name, p.stack_bytes);
        }
    }
}

// ------------------------------------------- kprobes, kretprobes, multi-probe

const SHADOW: &str = include_str!("../../../examples/shadow_open_ok.hny");

fn asm_of(src: &str, arch: Arch, idx: usize) -> String {
    let prog = parse(src).unwrap();
    let c = compile(&prog, arch).unwrap_or_else(|e| panic!("codegen failed: {e}"));
    disasm_bytes(&c.programs[idx].bytecode)
}

#[test]
fn two_probes_become_two_programs_sharing_maps() {
    let prog = parse(SHADOW).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert_eq!(c.programs.len(), 2);
    assert_eq!(c.programs[0].name, "kprobe:do_sys_openat2");
    assert_eq!(c.programs[1].name, "kretprobe:do_sys_openat2");
    assert_eq!(c.maps.len(), 1);
    // Both programs reference the same map index.
    assert!(disasm_bytes(&c.programs[0].bytecode).contains("map_fd(1)"));
    assert!(disasm_bytes(&c.programs[1].bytecode).contains("map_fd(1)"));
}

#[test]
fn kprobe_arg_reads_pt_regs_per_arch() {
    // arg(1): aarch64 x1 at +8, x86_64 rsi at +104.
    assert!(asm_of(SHADOW, Arch::Aarch64, 0).contains("ldx64 r0, [r0 +8]"));
    assert!(asm_of(SHADOW, Arch::X86_64, 0).contains("ldx64 r0, [r0 +104]"));
}

#[test]
fn retval_reads_return_register_and_compares_signed() {
    let a = asm_of(SHADOW, Arch::Aarch64, 1);
    assert!(a.contains("ldx64 r0, [r0 +0]"), "aarch64 x0\n{a}");
    // `fd >= 0` on an i64 must be a signed jump, or -EACCES would look huge.
    assert!(a.contains("s>="), "expected signed compare\n{a}");
    let x = asm_of(SHADOW, Arch::X86_64, 1);
    assert!(x.contains("ldx64 r0, [r0 +80]"), "x86_64 rax\n{x}");
}

#[test]
fn records_carry_an_event_id_header() {
    // Every emit writes the event id at offset 0 and reserves header + size.
    let text = asm(EXEC);
    assert!(text.contains("st32 [r6 +0], 0"), "{text}");
    assert!(text.contains("mov r2, 32"), "24-byte Exec + 8-byte header\n{text}");
    let prog = parse(SHADOW).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert_eq!(c.events[0].name, "ShadowOpen");
    let ret = disasm_bytes(&c.programs[1].bytecode);
    assert!(ret.contains("st32 [r6 +0], 0"), "{ret}");
}

#[test]
fn unsigned_compares_stay_unsigned() {
    // exec_burst compares u64s: no signed jump anywhere.
    assert!(!asm(EXEC_BURST).contains(" s>"), "{}", asm(EXEC_BURST));
}

// --------------------------------------------------------------- lsm hooks

const LSM: &str = include_str!("../../../examples/lsm_block_uid.hny");

#[test]
fn lsm_probe_compiles_to_an_lsm_program() {
    let prog = parse(LSM).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert_eq!(c.programs.len(), 1);
    assert_eq!(c.programs[0].name, "lsm:file_open");
    assert!(matches!(&c.programs[0].kind, honeyc::codegen::ProbeKind::Lsm { hook } if hook == "file_open"));
}

#[test]
fn deny_returns_minus_one_and_allow_returns_zero() {
    let asm = disasm_bytes(&compile(&parse(LSM).unwrap(), Arch::Aarch64).unwrap().programs[0].bytecode);
    // deny(): mov r0, -1 then exit.
    assert!(asm.contains("mov r0, -1"), "{asm}");
    // the fall-through allow path: mov r0, 0 then exit.
    assert!(asm.trim_end().ends_with("mov r0, 0\n  33: exit") || asm.contains("mov r0, 0"), "{asm}");
    // both an early deny-exit and a final allow-exit exist.
    assert_eq!(asm.matches("exit").count(), 2, "{asm}");
}

#[test]
fn lsm_arg_reads_the_context_array_directly() {
    // In an LSM probe arg(n) is at ctx + 8n (no +16 tracepoint header).
    let src = "event E { a: u64 } probe lsm(\"file_open\") { emit E { a: arg(0) }; }";
    let asm = disasm_bytes(&compile(&parse(src).unwrap(), Arch::Aarch64).unwrap().programs[0].bytecode);
    assert!(asm.contains("ldx64 r0, [r0 +0]"), "arg(0) at ctx+0\n{asm}");
    let src = "event E { a: u64 } probe lsm(\"file_open\") { emit E { a: arg(2) }; }";
    let asm = disasm_bytes(&compile(&parse(src).unwrap(), Arch::Aarch64).unwrap().programs[0].bytecode);
    assert!(asm.contains("ldx64 r0, [r0 +16]"), "arg(2) at ctx+16\n{asm}");
}

// --------------------------------------------------------------------- xdp

const ICMP: &str = include_str!("../../../examples/icmp_drop.hny");

#[test]
fn xdp_prologue_loads_packet_bounds_and_checks_once() {
    let text = asm(ICMP);
    // data/data_end from the xdp_md context into callee-saved r7/r8.
    assert!(text.contains("ldx32 r7, [r1 +0]"), "{text}");
    assert!(text.contains("ldx32 r8, [r1 +4]"), "{text}");
    // one entry check: r2 = r7 + 34 (u32 at offset 30); if r2 > r8 -> pass
    assert!(text.contains("mov r2, r7"), "{text}");
    assert!(text.contains("add r2, 34"), "{text}");
    assert!(text.contains("if r2 > r8 goto"), "{text}");
    assert_eq!(text.matches("if r2 > r8 goto").count(), 1, "exactly one bounds check\n{text}");
}

#[test]
fn xdp_reads_are_plain_loads_with_byte_swaps() {
    let text = asm(ICMP);
    assert!(text.contains("ldx16 r0, [r7 +12]"), "{text}");
    assert!(text.contains("bswap16 r0"), "{text}");
    assert!(text.contains("ldx32 r0, [r7 +26]"), "{text}");
    assert!(text.contains("bswap32 r0"), "{text}");
    assert!(text.contains("ldx8 r0, [r7 +23]"), "{text}");
    // no swap after a u8 load
    let after_u8 = text.split("ldx8 r0, [r7 +23]").nth(1).unwrap();
    assert!(!after_u8.lines().nth(1).unwrap().contains("bswap"), "{text}");
}

#[test]
fn xdp_returns_drop_and_defaults_to_pass() {
    let text = asm(ICMP);
    assert!(text.contains("mov r0, 1\n"), "drop = XDP_DROP (1)\n{text}");
    // the epilogue (last two instructions) returns XDP_PASS (2)
    let lines: Vec<&str> = text.trim_end().lines().collect();
    assert!(lines[lines.len() - 2].ends_with("mov r0, 2"), "{text}");
    assert!(lines[lines.len() - 1].ends_with("exit"), "{text}");
}

#[test]
fn xdp_program_kind_and_no_bounds_check_without_reads() {
    let prog = parse(ICMP).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert!(matches!(&c.programs[0].kind, honeyc::codegen::ProbeKind::Xdp { interface } if interface == "lo"));
    let src = "event E { t: u64 } probe xdp(\"lo\") { emit E { t: ktime() }; }";
    let prog = parse(src).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    let text = disasm_bytes(&c.programs[0].bytecode);
    assert!(!text.contains("if r2 > r8"), "no reads, no check\n{text}");
}

// ------------------------------------------------------ uprobes & sampling

#[test]
fn uprobe_kinds_and_pt_regs_args() {
    let src = "event E { p: u64 } probe uprobe(\"/lib/libc.so.6:getenv\") { emit E { p: arg(0) }; }";
    let prog = parse(src).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert!(matches!(&c.programs[0].kind, honeyc::codegen::ProbeKind::Uprobe { target } if target == "/lib/libc.so.6:getenv"));
    // arg(0) reads pt_regs like a kprobe: aarch64 x0 at +0.
    let asm = disasm_bytes(&c.programs[0].bytecode);
    assert!(asm.contains("ldx64 r0, [r0 +0]"), "{asm}");
    // x86_64 uses rdi at +112.
    let cx = compile(&prog, Arch::X86_64).unwrap();
    assert!(disasm_bytes(&cx.programs[0].bytecode).contains("ldx64 r0, [r0 +112]"));
}

#[test]
fn sample_creates_one_counter_map_sized_to_the_sites() {
    let src = "event E { a: u32 } probe tracepoint(\"s\",\"n\") { if sample(10) { emit E { a: 1 }; } if sample(20) { emit E { a: 2 }; } }";
    let prog = parse(src).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    let m = c.maps.iter().find(|m| m.name == "__honey_sample").expect("hidden sample map");
    assert_eq!(m.kind, honeyc::codegen::MapKind::Array);
    assert_eq!(m.max_entries, 2, "one counter per call site");
}

#[test]
fn sample_increments_a_counter_and_tests_the_rate() {
    let src = "event E { a: u32 } probe tracepoint(\"s\",\"n\") { if sample(100) { emit E { a: 1 }; } }";
    let asm = asm_helper(src);
    assert!(asm.contains("call 1"), "map_lookup_elem\n{asm}");   // lookup
    assert!(asm.contains("add r1, 1"), "increment\n{asm}");
    assert!(asm.contains("mod r1, 100"), "1-in-100\n{asm}");
}

fn asm_helper(src: &str) -> String {
    let prog = parse(src).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    disasm_bytes(&c.programs[0].bytecode)
}

#[test]
fn no_sample_map_when_unused() {
    let prog = parse(EXEC).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert!(!c.maps.iter().any(|m| m.name == "__honey_sample"));
}

// ---------------------------------------------------------- string equality

const SHELL: &str = include_str!("../../../examples/exec_shell.hny");

/// Count terminator checks: a byte load immediately followed by `!= 0`.
/// (A plain `if r0 != 0 goto` also appears for boolean conditions.)
fn nul_checks(text: &str) -> usize {
    let lines: Vec<&str> = text.lines().collect();
    lines
        .windows(2)
        .filter(|w| w[0].contains("ldx8 r0, [r10") && w[1].contains("if r0 != 0 goto"))
        .count()
}

#[test]
fn string_equality_checks_every_byte_then_the_terminator() {
    // "/bin/sh" is 7 bytes into a str<32>: 7 byte compares + 1 NUL check.
    let src = "event E { a: u8 } probe tracepoint(\"s\",\"n\") { let p: str<32> = read_user_str(arg(0)); if p == \"/bin/sh\" { emit E { a: 1 }; } }";
    let text = asm_helper(src);
    // first byte '/' = 47, last byte 'h' = 104, then the terminator at +7.
    assert!(text.contains("if r0 != 47 goto"), "{text}");
    assert!(text.contains("if r0 != 104 goto"), "{text}");
    assert_eq!(nul_checks(&text), 1, "one NUL check\n{text}");
}

#[test]
fn string_inequality_flips_the_result() {
    let src = "event E { b: bool } probe tracepoint(\"s\",\"n\") { let p: str<8> = read_user_str(arg(0)); emit E { b: p != \"x\" }; }";
    let text = asm_helper(src);
    assert!(text.contains("xor r0, 1"), "{text}");
}

#[test]
fn literal_filling_the_capacity_has_no_terminator_check() {
    let src = "event E { a: u8 } probe tracepoint(\"s\",\"n\") { let p: str<2> = read_user_str(arg(0)); if p == \"ab\" { emit E { a: 1 }; } }";
    let text = asm_helper(src);
    assert_eq!(nul_checks(&text), 0, "{text}");
}

#[test]
fn two_locals_compare_bytewise_and_stop_at_a_shared_nul() {
    let src = "event E { a: u8 } probe tracepoint(\"s\",\"n\") { let p: str<4> = read_user_str(arg(0)); let q: str<8> = read_user_str(arg(1)); if p == q { emit E { a: 1 }; } }";
    let text = asm_helper(src);
    // 4 bytes compared pairwise (min capacity), each with a NUL early-exit,
    // then q must end at index 4.
    assert_eq!(text.matches("if r1 != r0 goto").count(), 4, "{text}");
    assert_eq!(text.matches("if r1 == 0 goto").count(), 4, "{text}");
    assert!(text.contains("ldx8 r0, [r10 -"), "{text}");
}

#[test]
fn exec_shell_example_compiles() {
    let prog = parse(SHELL).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert_eq!(c.events[0].name, "Shell");
}

// ------------------------------------------------------------ usdt & ipv4

#[test]
fn usdt_program_kind() {
    let src = "event E { p: u32 } probe usdt(\"/work/linux/usdt_demo:honey:tick\") { emit E { p: pid() }; }";
    let prog = parse(src).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    assert!(matches!(&c.programs[0].kind, honeyc::codegen::ProbeKind::Usdt { target } if target.ends_with(":honey:tick")));
    assert_eq!(c.programs[0].name, "usdt:/work/linux/usdt_demo:honey:tick");
}

#[test]
fn ipv4_field_is_four_bytes_stored_as_a_word() {
    let src = "event E { src: ipv4, ttl: u8 } probe xdp(\"lo\") { emit E { src: pkt.u32(26), ttl: pkt.u8(22) }; }";
    let prog = parse(src).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    let f = &c.events[0].fields[0];
    assert_eq!(f.kind, honeyc::layout::FieldKind::Ipv4);
    assert_eq!((f.offset, f.size), (0, 4));
    assert_eq!(c.events[0].size, 8, "ipv4@0 (4) + ttl@4 (1) rounds to 8");
    let text = disasm_bytes(&c.programs[0].bytecode);
    assert!(text.contains("stx32 [r6 +8], r0"), "ipv4 stored as a 32-bit word past the header\n{text}");
}

// ------------------------------------------------------------- usdt args

#[test]
fn usdt_reserves_one_arg_spec_per_program() {
    let src = "event E { a: u64 } probe usdt(\"/b:p:n\") { emit E { a: arg(0) }; } probe kprobe(\"f\") { emit E { a: arg(0) }; }";
    let prog = parse(src).unwrap();
    let c = compile(&prog, Arch::Aarch64).unwrap();
    let m = c.maps.iter().find(|m| m.name == "__honey_usdt").expect("hidden usdt spec map");
    assert_eq!(m.kind, honeyc::codegen::MapKind::Array);
    assert_eq!(m.value_size, honeyc::codegen::USDT_SPEC_SIZE);
    assert_eq!(m.max_entries, 2, "keyed by program index, so one per program");
    // no spec map when there is no usdt probe
    let c2 = compile(&parse(EXEC).unwrap(), Arch::Aarch64).unwrap();
    assert!(!c2.maps.iter().any(|m| m.name == "__honey_usdt"));
}

#[test]
fn usdt_arg_is_a_spec_driven_read() {
    let src = "event E { a: u64 } probe usdt(\"/b:p:n\") { emit E { a: arg(2) }; }";
    let text = asm_helper(src);
    // spec lookup keyed by this program's index (0), kept in r9
    assert!(text.contains("st32 [r10 -"), "{text}");
    assert!(text.contains("call 1"), "map_lookup_elem\n{text}");
    assert!(text.contains("mov r9, r0"), "{text}");
    // arg 2's spec lives 32 bytes in: kind at +32, signed +33, shift +34, reg_off +36, val +40
    assert!(text.contains("ldx8 r1, [r9 +32]"), "kind\n{text}");
    assert!(text.contains("ldx16 r2, [r9 +36]"), "reg_off\n{text}");
    assert!(text.contains("ldx64 r0, [r9 +40]"), "const value\n{text}");
    // register read from ctx, then optional user deref, then sized extract
    assert!(text.contains("call 113"), "probe_read_kernel of the register\n{text}");
    assert!(text.contains("call 112"), "probe_read_user for memory operands\n{text}");
    assert!(text.contains("lsh r0, r4") && text.contains("arsh r0, r4") && text.contains("rsh r0, r4"), "{text}");
}
