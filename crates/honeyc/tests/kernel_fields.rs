//! Struct-field reads from kprobe pointer arguments (stage: CO-RE-lite).
//!
//! Uses a small synthetic kernel BTF (see `common::kernel_btf`) so the tests
//! need no real kernel: file, path, dentry, qstr with realistic offsets.

mod common;

use common::kernel_btf;
use honeyc::codegen::{compile_with_btf, Arch};
use honeyc::parser::parse;
use honeyc::typeck::{check_with_btf, Diag};

fn prog(body: &str) -> String {
    format!("event E {{ a: u32, path: str<32> }}\nprobe kprobe(\"vfs_open\") {{\n{body}\n}}")
}

fn check_ok(src: &str) {
    let btf = kernel_btf();
    let p = parse(src).unwrap();
    if let Err(d) = check_with_btf(&p, Some(&btf)) {
        panic!("expected ok, got: {d:#?}");
    }
}

fn check_err(src: &str) -> Vec<Diag> {
    let btf = kernel_btf();
    let p = parse(src).unwrap();
    match check_with_btf(&p, Some(&btf)) {
        Ok(_) => panic!("expected a type error, but it passed"),
        Err(d) => d,
    }
}

fn first(src: &str) -> String {
    check_err(src).remove(0).message
}

// ------------------------------------------------------------- type checker

#[test]
fn a_valid_field_chain_typechecks() {
    check_ok(&prog(
        "    let p: ptr<path> = arg(0);\n    let s: str<32> = read_kernel_str(p.dentry.d_name.name);\n    emit E { a: 1, path: s };",
    ));
}

#[test]
fn scalar_field_has_the_btf_width() {
    // f_flags is u32 in the synthetic BTF; storing it in a u32 is fine.
    check_ok("event E { flags: u32 }\nprobe kprobe(\"vfs_open\") {\n    let f: ptr<file> = arg(1);\n    emit E { flags: f.f_flags };\n}");
    // ... but not in a u16 (no implicit narrowing).
    let msg = first("event E { flags: u16 }\nprobe kprobe(\"vfs_open\") {\n    let f: ptr<file> = arg(1);\n    emit E { flags: f.f_flags };\n}");
    assert!(msg.contains("expected `u16`, found `u32`"), "{msg}");
}

#[test]
fn using_a_pointer_field_without_btf_is_an_error() {
    let src = "event E { a: u32 }\nprobe kprobe(\"vfs_open\") {\n    let f: ptr<file> = arg(1);\n    emit E { a: f.f_flags };\n}";
    let p = parse(src).unwrap();
    let err = check_with_btf(&p, None).unwrap_err();
    assert!(err.iter().any(|d| d.message.contains("needs the kernel's type information")), "{err:#?}");
}

#[test]
fn unknown_struct_is_rejected() {
    let msg = first("event E { a: u32 }\nprobe kprobe(\"vfs_open\") {\n    let x: ptr<nope> = arg(0);\n    emit E { a: 1 };\n}");
    assert!(msg.contains("`nope` is not a kernel struct"), "{msg}");
}

#[test]
fn unknown_field_is_rejected() {
    let msg = first("event E { a: u32 }\nprobe kprobe(\"vfs_open\") {\n    let p: ptr<path> = arg(0);\n    let d: ptr<dentry> = p.nosuch;\n    emit E { a: 1 };\n}");
    assert!(msg.contains("has no field `nosuch`"), "{msg}");
}

#[test]
fn a_field_on_a_non_pointer_is_rejected() {
    let msg = first("event E { a: u32 }\nprobe kprobe(\"vfs_open\") {\n    let x = 1;\n    let y = x.foo;\n    emit E { a: 1 };\n}");
    assert!(msg.contains("needs a kernel struct pointer"), "{msg}");
}

#[test]
fn read_kernel_str_needs_a_bounded_destination() {
    let msg = first("event E { a: u32 }\nprobe kprobe(\"vfs_open\") {\n    let p: ptr<path> = arg(0);\n    let s = read_kernel_str(p.dentry.d_name.name);\n    emit E { a: 1 };\n}");
    assert!(msg.contains("needs a bounded destination"), "{msg}");
}

// ------------------------------------------------------------------ codegen

fn asm(src: &str) -> String {
    let btf = kernel_btf();
    let p = parse(src).unwrap();
    let c = compile_with_btf(&p, Arch::Aarch64, Some(&btf)).unwrap_or_else(|e| panic!("{e}"));
    // decode program 0
    let bytes = &c.programs[0].bytecode;
    let mut insns = Vec::new();
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let op = bytes[i];
        let dst = bytes[i + 1] & 0xf;
        let src = bytes[i + 1] >> 4;
        let off = i16::from_le_bytes([bytes[i + 2], bytes[i + 3]]);
        let imm = i32::from_le_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]);
        if op == 0x18 {
            let hi = i32::from_le_bytes([bytes[i + 12], bytes[i + 13], bytes[i + 14], bytes[i + 15]]);
            insns.push(honeyc::bpf::Insn::from_parts(op, dst, src, off, imm, Some(hi)));
            i += 16;
        } else {
            insns.push(honeyc::bpf::Insn::from_parts(op, dst, src, off, imm, None));
            i += 8;
        }
    }
    honeyc::bpf::disasm_prog(&insns)
}

const CHAIN: &str = "event E { file: str<32> }\nprobe kprobe(\"vfs_open\") {\n    let p: ptr<path> = arg(0);\n    let s: str<32> = read_kernel_str(p.dentry.d_name.name);\n    emit E { file: s };\n}";

#[test]
fn field_chain_records_one_reloc_per_hop() {
    let btf = kernel_btf();
    let p = parse(CHAIN).unwrap();
    let c = compile_with_btf(&p, Arch::Aarch64, Some(&btf)).unwrap();
    let relocs = &c.programs[0].relocs;
    // path.dentry (read), dentry.d_name (embedded), qstr.name (read).
    let names: Vec<(&str, &str)> = relocs.iter().map(|r| (r.struct_name.as_str(), r.field.as_str())).collect();
    assert_eq!(names, vec![("path", "dentry"), ("dentry", "d_name"), ("qstr", "name")], "{relocs:#?}");
}

#[test]
fn reloc_slots_point_at_add_instructions_with_the_compile_time_offset() {
    let btf = kernel_btf();
    let p = parse(CHAIN).unwrap();
    let c = compile_with_btf(&p, Arch::Aarch64, Some(&btf)).unwrap();
    let bytes = &c.programs[0].bytecode;
    for r in &c.programs[0].relocs {
        let at = r.slot * 8;
        let opcode = bytes[at];
        // 0x07 = ALU64 | ADD | K (add reg, imm)
        assert_eq!(opcode, 0x07, "reloc slot must be an add instruction");
        let imm = i32::from_le_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]]);
        // synthetic offsets: dentry@8, d_name@32, name@8
        let expect = match (r.struct_name.as_str(), r.field.as_str()) {
            ("path", "dentry") => 8,
            ("dentry", "d_name") => 32,
            ("qstr", "name") => 8,
            _ => panic!("unexpected reloc"),
        };
        assert_eq!(imm, expect, "{}.{}", r.struct_name, r.field);
    }
}

#[test]
fn embedded_struct_field_adds_offset_pointer_field_reads() {
    // f_path is embedded (add), so no probe_read for it; dentry is a pointer
    // (a probe_read_kernel call). Count the kernel reads: dentry, name = 2.
    let src = "event E { file: str<32> }\nprobe kprobe(\"vfs_open\") {\n    let f: ptr<file> = arg(1);\n    let s: str<32> = read_kernel_str(f.f_path.dentry.d_name.name);\n    emit E { file: s };\n}";
    let text = asm(src);
    assert_eq!(text.matches("call 113").count(), 2, "two pointer reads\n{text}");
    assert_eq!(text.matches("call 115").count(), 1, "one string read\n{text}");
}
