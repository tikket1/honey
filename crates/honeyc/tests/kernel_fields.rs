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

// ------------------------------------------------- packet struct views (XDP)

fn xdp(body: &str) -> String {
    format!("event E {{ a: u32, m: mac, b: bool }}\nprobe xdp(\"lo\") {{\n{body}\n}}")
}

#[test]
fn packet_views_type_fields_from_btf() {
    check_ok(&xdp("    let eth: ptr<ethhdr> = pkt.at(0);\n    let ip: ptr<iphdr> = pkt.at(14);\n    emit E { a: ip.saddr, m: eth.h_source, b: ip.protocol == 1 };"));
    // h_proto is a __be16 -> u16, not u32
    let msg = first(&xdp("    let eth: ptr<ethhdr> = pkt.at(0);\n    emit E { a: eth.h_proto, m: eth.h_dest, b: true };"));
    assert!(msg.contains("expected `u32`, found `u16`"), "{msg}");
}

#[test]
fn saddr_is_found_through_the_anonymous_union() {
    let btf = kernel_btf();
    let m = btf.member("iphdr", "saddr").expect("saddr via anonymous member");
    assert_eq!(m.offset_bytes, 12);
    let d = btf.member("iphdr", "daddr").unwrap();
    assert_eq!(d.offset_bytes, 16);
    assert!(matches!(btf.resolve(m.type_id), honeyc::btf::Resolved::Int { bytes: 4, big_endian: true, .. }));
    assert!(btf.member("iphdr", "ihl").unwrap().bitfield);
    assert_eq!(btf.struct_size("iphdr"), Some(20));
}

#[test]
fn bitfields_pointers_and_unbound_views_are_errors() {
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    emit E { a: 1, m: pkt.mac(0), b: ip.ihl == 5 };"));
    assert!(msg.contains("`ihl` is a bitfield"), "{msg}");
    let msg = first(&xdp("    let x = pkt.at(14);\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("`pkt.at(offset)` needs a struct type"), "{msg}");
    let msg = first(&xdp("    let f: ptr<file> = pkt.at(0);\n    emit E { a: 1, m: pkt.mac(0), b: f.f_path.dentry.d_name.name == \"x\" };"));
    assert!(msg.contains("is a pointer; packet structs are read by value") || msg.contains("cannot compare"), "{msg}");
    // a view past the bound
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(240);\n    emit E { a: ip.saddr, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("ends past 256 bytes"), "{msg}");
    // views only in xdp
    let msg = first("event E { a: u32 } probe kprobe(\"f\") { let ip: ptr<iphdr> = pkt.at(14); emit E { a: ip.saddr }; }");
    assert!(msg.contains("only available in an `xdp` probe"), "{msg}");
}

fn asm_xdp(body: &str) -> String {
    asm(&xdp(body))
}

#[test]
fn view_fields_are_plain_loads_swapped_when_big_endian() {
    let text = asm_xdp("    let eth: ptr<ethhdr> = pkt.at(0);\n    let ip: ptr<iphdr> = pkt.at(14);\n    emit E { a: ip.saddr, m: eth.h_source, b: eth.h_proto == 0x0800 };");
    // saddr: 14 + 12 = 26, a 32-bit load then bswap32
    assert!(text.contains("ldx32 r0, [r7 +26]"), "{text}");
    assert!(text.contains("bswap32 r0"), "{text}");
    // h_proto: 16-bit load at 12 then bswap16
    assert!(text.contains("ldx16 r0, [r7 +12]"), "{text}");
    assert!(text.contains("bswap16 r0"), "{text}");
    // h_source: a 6-byte copy from packet offset 6 (4 + 2)
    assert!(text.contains("ldx32 r0, [r7 +6]") && text.contains("ldx16 r0, [r7 +10]"), "{text}");
    // the bound covers the iphdr view: 14 + 20 = 34
    assert!(text.contains("add r2, 34"), "{text}");
    // a view is compile-time only: nothing stored for eth/ip
    assert!(!text.contains("stx64 [r10 -16]"), "{text}");
}

#[test]
fn protocol_read_is_an_unswapped_byte() {
    let text = asm_xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    emit E { a: 1, m: pkt.mac(0), b: ip.protocol == 1 };");
    assert!(text.contains("ldx8 r0, [r7 +23]"), "{text}");
    let after = text.split("ldx8 r0, [r7 +23]").nth(1).unwrap();
    assert!(!after.lines().nth(1).unwrap().contains("bswap"), "{text}");
}

// ------------------------------------------------------------- in_subnet

#[test]
fn in_subnet_types_and_validation() {
    check_ok(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    emit E { a: 1, m: pkt.mac(0), b: in_subnet(ip.saddr, \"10.0.0.0/8\") };"));
    check_ok(&xdp("    let s = pkt.ipv6(22);\n    emit E { a: 1, m: pkt.mac(0), b: in_subnet(s, \"fe80::/10\") };"));
    let msg = first(&xdp("    emit E { a: 1, m: pkt.mac(0), b: in_subnet(pkt.u32(26), \"10.0.0.0/33\") };"));
    assert!(msg.contains("is not an IPv4 CIDR"), "{msg}");
    let msg = first(&xdp("    let s = pkt.ipv6(22);\n    emit E { a: 1, m: pkt.mac(0), b: in_subnet(s, \"10.0.0.0/8\") };"));
    assert!(msg.contains("is not an IPv6 CIDR"), "{msg}");
    let msg = first(&xdp("    let m = pkt.mac(0);\n    emit E { a: 1, m: m, b: in_subnet(m, \"10.0.0.0/8\") };"));
    assert!(msg.contains("needs a `u32` or `ipv6` address"), "{msg}");
}

#[test]
fn in_subnet_compiles_to_mask_and_compare() {
    // u32: (addr & 0xff000000) == 0x0a000000
    let text = asm_xdp("    emit E { a: 1, m: pkt.mac(0), b: in_subnet(pkt.u32(26), \"10.0.0.0/8\") };");
    assert!(text.contains("4278190080") || text.contains("-16777216"), "mask 0xff000000\n{text}");
    assert!(text.contains("and r0, r1"), "{text}");
    assert!(text.contains("167772160"), "net 10.0.0.0\n{text}");
    // ipv6 fe80::/10: only the first 8-byte chunk has mask bits; one compare
    let text = asm_xdp("    let s = pkt.ipv6(22);\n    emit E { a: 1, m: pkt.mac(0), b: in_subnet(s, \"fe80::/10\") };");
    assert_eq!(text.matches("if r1 != r0 goto").count(), 1, "{text}");
    assert!(text.contains("and r1, r0"), "{text}");
    // ::1/128 needs both chunks
    let text = asm_xdp("    let s = pkt.ipv6(22);\n    emit E { a: 1, m: pkt.mac(0), b: in_subnet(s, \"::1/128\") };");
    assert_eq!(text.matches("if r1 != r0 goto").count(), 2, "{text}");
}
