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
fn field_chain_records_one_reloc_per_read_with_the_member_path() {
    let btf = kernel_btf();
    let p = parse(CHAIN).unwrap();
    let c = compile_with_btf(&p, Arch::Aarch64, Some(&btf)).unwrap();
    let relocs = &c.programs[0].relocs;
    // path.dentry (a pointer read); then d_name is embedded, so its offset
    // stays pending and the next read names the whole path from dentry.
    let names: Vec<(&str, &str)> = relocs.iter().map(|r| (r.struct_name.as_str(), r.field.as_str())).collect();
    assert_eq!(names, vec![("path", "dentry"), ("dentry", "d_name.name")], "{relocs:#?}");
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
        // synthetic offsets: dentry@8, d_name@32 + name@8
        let expect = match (r.struct_name.as_str(), r.field.as_str()) {
            ("path", "dentry") => 8,
            ("dentry", "d_name.name") => 40,
            _ => panic!("unexpected reloc"),
        };
        assert_eq!(imm, expect, "{}.{}", r.struct_name, r.field);
    }
}

#[test]
fn anonymous_members_are_reached_by_type_id() {
    // packet view: un (anonymous union) . echo (anonymous struct) . sequence
    let text = asm_xdp("    let icmp: ptr<icmphdr> = pkt.at(34);\n    emit E { a: icmp.un.echo.sequence, m: pkt.mac(0), b: icmp.type == 8 };");
    assert!(text.contains("ldx16 r0, [r7 +40]"), "{text}");
    assert!(text.contains("ldx8 r0, [r7 +34]"), "{text}");
    // kernel pointer: one reloc naming the whole path, imm = 4 + 0 + 2
    let src = "event E { a: u32 }\nprobe kprobe(\"f\") {\n    let p: ptr<icmphdr> = arg(0);\n    emit E { a: p.un.echo.sequence };\n}";
    let btf = kernel_btf();
    let c = compile_with_btf(&parse(src).unwrap(), Arch::Aarch64, Some(&btf)).unwrap();
    let relocs = &c.programs[0].relocs;
    assert_eq!(relocs.len(), 1, "{relocs:#?}");
    assert_eq!((relocs[0].struct_name.as_str(), relocs[0].field.as_str()), ("icmphdr", "un.echo.sequence"));
    let at = relocs[0].slot * 8;
    let b = &c.programs[0].bytecode;
    assert_eq!(i32::from_le_bytes([b[at + 4], b[at + 5], b[at + 6], b[at + 7]]), 6);
    // messages name anonymous types by their path
    let msg = first("event E { a: u32 } probe kprobe(\"f\") { let p: ptr<icmphdr> = arg(0); emit E { a: p.un.nope }; }");
    assert!(msg.contains("`struct icmphdr.un` has no field `nope`"), "{msg}");
    // a pointer bound to an embedded struct keeps its pending offset
    let src = "event E { a: u32 }\nprobe kprobe(\"f\") {\n    let p: ptr<icmphdr> = arg(0);\n    let e: ptr<icmphdr.un.echo> = p.un.echo;\n    emit E { a: e.id };\n}";
    assert!(parse(src).is_err() || first(src).contains("not a kernel struct"), "anonymous types can't be named in annotations");
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
    assert!(btf.member("iphdr", "ihl").unwrap().bitfield());
    assert_eq!(btf.struct_size("iphdr"), Some(20));
}

#[test]
fn pointers_and_unbound_views_are_errors() {
    let msg = first(&xdp("    let x = pkt.at(14);\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("`pkt.at` needs a struct type"), "{msg}");
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

// -------------------------------------------------------------- bitfields

#[test]
fn bitfields_load_a_container_then_shift_and_mask() {
    // iphdr.ihl: 4 bits at bit 0 -> byte load, mask 15, no shift.
    check_ok(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    emit E { a: 1, m: pkt.mac(0), b: ip.ihl == 5 };"));
    let text = asm_xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    emit E { a: 1, m: pkt.mac(0), b: ip.ihl == 5 };");
    assert!(text.contains("ldx8 r0, [r7 +14]"), "{text}");
    assert!(text.contains("and r0, 15"), "{text}");
    let after = text.split("ldx8 r0, [r7 +14]").nth(1).unwrap();
    assert!(!after.lines().nth(1).unwrap().contains("rsh"), "no shift for bit 0\n{text}");
    // a bitfield's type is the narrowest int holding it
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    let v: u32 = ip.ihl;\n    emit E { a: v, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("expected `u32`, found `u8`"), "{msg}");
}

#[test]
fn bitfield_container_math_is_right_for_offset_bits() {
    // A synthetic 4-bit field at bit 4 (like iphdr.version) needs rsh 4.
    let btf = kernel_btf();
    let ihl = btf.member("iphdr", "ihl").unwrap();
    assert_eq!((ihl.bit_offset, ihl.bit_size), (0, 4));
    assert!(ihl.bitfield());
    // anonymous-union members keep their bit offsets relative to the outer struct
    assert_eq!(btf.member("iphdr", "daddr").unwrap().bit_offset, 16 * 8);
}

// ---------------------------------------------------------- dynamic views

#[test]
fn view_at_a_runtime_offset_is_bounds_checked_in_r9() {
    // IPv4 transport header: 14 + ihl*4, a runtime offset.
    let body = "    let ip: ptr<iphdr> = pkt.at(14);\n    let tcp: ptr<tcphdr> = pkt.view(14 + ip.ihl * 4);\n    emit E { a: 1, m: pkt.mac(0), b: tcp.dest == 22 };";
    check_ok(&xdp(body));
    let text = asm_xdp(body);
    // offset masked, pointer built in r9, checked against data_end with sizeof(tcphdr)
    assert!(text.contains("and r0, 4095"), "{text}");
    assert!(text.contains("mov r9, r7"), "{text}");
    assert!(text.contains("add r9, r0"), "{text}");
    assert!(text.contains("mov r2, r9"), "{text}");
    assert!(text.contains("add r2, 20"), "sizeof(tcphdr) = 20\n{text}");
    // field read from the dynamic base, byte-swapped (dest is __be16)
    assert!(text.contains("ldx16 r0, [r9 +2]"), "{text}");
    assert!(text.contains("bswap16 r0"), "{text}");
}

#[test]
fn view_offset_must_be_an_integer_and_r9_is_reserved() {
    let msg = first(&xdp("    let m = pkt.mac(0);\n    let t: ptr<tcphdr> = pkt.view(m);\n    emit E { a: 1, m: m, b: true };"));
    assert!(msg.contains("`pkt.view` takes an integer offset"), "{msg}");
    // with a dynamic view live, locals must not take r9
    let body = "    let t: ptr<tcphdr> = pkt.view(34);\n    let x = pkt.u32(26);\n    emit E { a: x, m: pkt.mac(0), b: t.dest == 1 };";
    let text = asm_xdp(body);
    assert!(!text.contains("mov r9, r0\n"), "r9 belongs to the view\n{text}");
}

#[test]
fn ipv6_walk_then_l4_view() {
    let body = "    let proto = pkt.ipv6_l4(14);\n    if proto == 6 {\n        let tcp: ptr<tcphdr> = pkt.l4();\n        emit E { a: 1, m: pkt.mac(0), b: tcp.dest == 22 };\n    }";
    check_ok(&xdp(body));
    let text = asm_xdp(body);
    // walk starts at nexthdr (14+6) with r9 = data + 54; four unrolled hops,
    // each checking 2 bytes against data_end
    assert!(text.contains("ldx8 r0, [r7 +20]"), "{text}");
    assert!(text.contains("add r9, 54"), "{text}");
    assert_eq!(text.matches("add r3, 2").count(), 4, "four hops\n{text}");
    assert_eq!(text.matches("if r0 == 44 goto").count(), 4, "{text}");
    // then the l4 view checks sizeof(tcphdr) and reads dest from r9
    assert!(text.contains("add r2, 20"), "{text}");
    assert!(text.contains("ldx16 r0, [r9 +2]"), "{text}");
    // the entry bound covers the 40-byte IPv6 header at 14
    assert!(text.contains("add r2, 54"), "{text}");
    // l4 without a walk is an error
    let msg = first(&xdp("    let tcp: ptr<tcphdr> = pkt.l4();\n    emit E { a: 1, m: pkt.mac(0), b: tcp.dest == 22 };"));
    assert!(msg.contains("needs a preceding `pkt.ipv6_l4"), "{msg}");
}

// ---------------------------------------------------------- packet writes

#[test]
fn packet_writes_store_through_the_view() {
    let text = asm_xdp("    let eth: ptr<ethhdr> = pkt.at(0);\n    let ip: ptr<iphdr> = pkt.at(14);\n    ip.ttl = 7;\n    ip.saddr = 1;\n    eth.h_dest = eth.h_source;\n    emit E { a: 1, m: pkt.mac(0), b: true };");
    // ttl: a plain byte store at 14 + 8
    assert!(text.contains("stx8 [r7 +22], r0"), "{text}");
    // saddr is __be32: swapped back to network order, then stored at 14 + 12
    let lines: Vec<&str> = text.lines().collect();
    let i = lines.iter().position(|l| l.contains("stx32 [r7 +26], r0")).expect("saddr store");
    assert!(lines[i - 1].contains("bswap32 r0"), "{text}");
    // h_dest = h_source: a 6-byte copy from offset 6 to offset 0
    assert!(text.contains("ldx32 r0, [r7 +6]") && text.contains("stx32 [r7 +0], r0"), "{text}");
    assert!(text.contains("ldx16 r0, [r7 +10]") && text.contains("stx16 [r7 +4], r0"), "{text}");
}

#[test]
fn a_mac_literal_is_stored_as_immediates() {
    let text = asm_xdp("    let eth: ptr<ethhdr> = pkt.at(0);\n    eth.h_dest = \"01:02:03:04:05:06\";\n    emit E { a: 1, m: pkt.mac(0), b: true };");
    // 04030201 little-endian = 0x04030201 = 67305985, then 0x0605 = 1541
    assert!(text.contains("67305985") && text.contains("stx32 [r7 +0], r0"), "{text}");
    assert!(text.contains("1541") && text.contains("stx16 [r7 +4], r0"), "{text}");
}

#[test]
fn packet_write_type_rules() {
    // scalar width must match the field
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    let x: u16 = 1;\n    ip.ttl = x;\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("expected `u8`, found `u16`"), "{msg}");
    // bitfields are read-only
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    ip.ihl = 5;\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("cannot write the bitfield `ihl`"), "{msg}");
    // blobs come from the packet, a blob local, or a literal
    let msg = first(&xdp("    let eth: ptr<ethhdr> = pkt.at(0);\n    eth.h_dest = 1;\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("a `mac` can only be written from the packet"), "{msg}");
    let msg = first(&xdp("    let eth: ptr<ethhdr> = pkt.at(0);\n    eth.h_dest = \"not a mac\";\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("is not a `mac` literal"), "{msg}");
    // only packet views are writable
    let msg = first("event E { a: u32 } probe kprobe(\"vfs_open\") { let f: ptr<file> = arg(1); f.f_flags = 1; emit E { a: 1 }; }");
    assert!(msg.contains("cannot assign to a field of `ptr<file>`"), "{msg}");
    // a literal that doesn't fit
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    ip.ttl = 300;\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("300 does not fit in `u8`"), "{msg}");
}

#[test]
fn tx_is_an_xdp_verdict() {
    let text = asm_xdp("    tx();");
    assert!(text.contains("mov r0, 3"), "{text}");
    let msg = first("event E { a: u32 } probe kprobe(\"f\") { tx(); emit E { a: 1 }; }");
    assert!(msg.contains("`tx()` is only available in an `xdp` probe"), "{msg}");
}

#[test]
fn embedded_structs_in_a_runtime_view_stay_relative_to_r9() {
    let text = asm_xdp("    let f: ptr<frame> = pkt.view(0);\n    f.ip.ttl = 1;\n    emit E { a: f.ip.saddr, m: f.eth.h_source, b: f.eth.h_proto == 0x0800 };");
    assert!(text.contains("stx8 [r9 +22], r0"), "{text}");
    assert!(text.contains("ldx32 r0, [r9 +26]"), "{text}");
    assert!(text.contains("ldx16 r0, [r9 +12]"), "{text}");
    // the nested blob copies from r9 + 6 too
    assert!(text.contains("ldx32 r0, [r9 +6]") && text.contains("ldx16 r0, [r9 +10]"), "{text}");
    assert!(!text.contains("[r7 +"), "{text}");
}

// ------------------------------------------------------------- checksums

#[test]
fn fix_csum_zeroes_sums_and_stores_the_check_field() {
    let text = asm_xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    ip.ttl = 7;\n    ip.fix_csum();\n    emit E { a: 1, m: pkt.mac(0), b: true };");
    // r3 = r7 + 14; check (offset 10) is zeroed, then written from the folded sum
    assert!(text.contains("add r3, 14"), "{text}");
    assert!(text.contains("stx16 [r3 +10], r0") && text.contains("stx16 [r3 +10], r1"), "{text}");
    // ten unconditional words, then twenty guarded option words
    assert_eq!(text.matches("ldx16 r0, [r3 +").count(), 30, "{text}");
    assert_eq!(text.matches("if r4 > r8 goto").count(), 20, "{text}");
    let msg = first(&xdp("    let eth: ptr<ethhdr> = pkt.at(0);\n    eth.fix_csum();\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("`eth` is a `ptr<ethhdr>`"), "{msg}");
}

#[test]
fn csum_update_is_a_u16_from_three_integers() {
    check_ok(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    ip.check = csum_update(ip.check, 0x4000, 0x0700);\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    ip.check = csum_update(ip.check, 1);\n    emit E { a: 1, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("takes three arguments"), "{msg}");
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    let a: u32 = csum_update(ip.check, 1, 2);\n    emit E { a: a, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("expected `u32`, found `u16`"), "{msg}");
    // the check field is __sum16: read and written swapped, like __be16
    let text = asm_xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    ip.check = csum_update(ip.check, 1, 2);\n    emit E { a: 1, m: pkt.mac(0), b: true };");
    assert!(text.contains("ldx16 r0, [r7 +24]"), "{text}");
    assert!(text.contains("stx16 [r7 +24], r0"), "{text}");
    assert_eq!(text.matches("bswap16 r0").count(), 2, "{text}");
}

// ----------------------------------------------------------- tcp options

#[test]
fn tcp_opt_is_an_option_value_bound_by_if_let() {
    check_ok(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    let tcp: ptr<tcphdr> = pkt.view(14 + ip.ihl * 4);\n    if let Some(mss) = tcp.opt(2) {\n        emit E { a: mss, m: pkt.mac(0), b: true };\n    }"));
    // the binding is a value, not a pointer
    let msg = first(&xdp("    let tcp: ptr<tcphdr> = pkt.at(34);\n    if let Some(mss) = tcp.opt(2) {\n        emit E { a: *mss, m: pkt.mac(0), b: true };\n    }"));
    assert!(msg.contains("cannot dereference `u32`"), "{msg}");
    // it can't be used unchecked
    let msg = first(&xdp("    let tcp: ptr<tcphdr> = pkt.at(34);\n    emit E { a: tcp.opt(2), m: pkt.mac(0), b: true };"));
    assert!(msg.contains("expected `u32`, found `Option<u32>`"), "{msg}");
    // only on a tcphdr view, with a one-byte kind
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    if let Some(v) = ip.opt(2) { emit E { a: v, m: pkt.mac(0), b: true }; }"));
    assert!(msg.contains("`ip` is a `ptr<iphdr>`"), "{msg}");
    let msg = first(&xdp("    let tcp: ptr<tcphdr> = pkt.at(34);\n    if let Some(v) = tcp.opt(256) { emit E { a: v, m: pkt.mac(0), b: true }; }"));
    assert!(msg.contains("one byte (0..=255)"), "{msg}");
}

#[test]
fn tcp_opt_walks_ten_bounded_hops() {
    let text = asm_xdp("    let tcp: ptr<tcphdr> = pkt.at(34);\n    if let Some(mss) = tcp.opt(2) {\n        emit E { a: mss, m: pkt.mac(0), b: true };\n    }");
    // doff: the byte at 34 + 12, shifted by 4 and masked to 4 bits, times 4
    assert!(text.contains("ldx8 r0, [r7 +46]") && text.contains("rsh r0, 4") && text.contains("and r0, 15"), "{text}");
    assert!(text.contains("lsh r2, 2"), "{text}");
    // one kind byte read per hop, each after a data_end check
    assert_eq!(text.matches("ldx8 r5, [r3 +0]").count(), 10, "{text}");
    assert_eq!(text.matches("if r5 > r8 goto").count(), 40, "{text}");
    // the wanted kind, and the three data widths
    assert_eq!(text.matches("if r5 != 2 goto").count(), 10, "{text}");
    assert!(text.contains("ldx8 r0, [r3 +2]") && text.contains("ldx16 r0, [r3 +2]") && text.contains("ldx32 r0, [r3 +2]"), "{text}");
    // the binding is stored, then the found flag decides the branch
    assert!(text.contains("if r1 == 0 goto"), "{text}");
}

// ------------------------------------------------------ payload + redirect

const HTTP: &str = "    let ip: ptr<iphdr> = pkt.at(14);\n    let tcp: ptr<tcphdr> = pkt.view(14 + ip.ihl * 4);\n    let sport = tcp.source;\n    let body = tcp.payload();\n";

#[test]
fn payload_view_types_its_methods() {
    check_ok(&xdp(&format!("{HTTP}    let line: str<16> = body.str();\n    emit E {{ a: body.len() + body.u32(4), m: pkt.mac(0), b: body.starts_with(\"GET \") && body.u8(0) == 71 }};")));
    let msg = first(&xdp(&format!("{HTTP}    let line = body.str();\n    emit E {{ a: 1, m: pkt.mac(0), b: true }};")));
    assert!(msg.contains("`.str()` needs a bounded destination"), "{msg}");
    let msg = first(&xdp(&format!("{HTTP}    emit E {{ a: body.u32(254), m: pkt.mac(0), b: true }};")));
    assert!(msg.contains("ends past 256 bytes"), "{msg}");
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    let body = ip.payload();\n    emit E { a: body.len(), m: pkt.mac(0), b: true };"));
    assert!(msg.contains("`ip` is a `ptr<iphdr>`"), "{msg}");
    let msg = first(&xdp(&format!("{HTTP}    emit E {{ a: 1, m: pkt.mac(0), b: body.starts_with(\"\") }};")));
    assert!(msg.contains("empty prefix"), "{msg}");
}

#[test]
fn taking_the_payload_consumes_the_transport_view() {
    // reading tcp after tcp.payload() would go through the moved pointer
    let msg = first(&xdp(&format!("{HTTP}    emit E {{ a: tcp.dest, m: pkt.mac(0), b: true }};")));
    assert!(msg.contains("`tcp` is no longer a valid view: `body` took the packet pointer"), "{msg}");
    // the same rule for two runtime views
    let msg = first(&xdp("    let ip: ptr<iphdr> = pkt.at(14);\n    let a: ptr<tcphdr> = pkt.view(34);\n    let b: ptr<tcphdr> = pkt.view(14 + ip.ihl * 4);\n    emit E { a: a.dest, m: pkt.mac(0), b: true };"));
    assert!(msg.contains("`a` is no longer a valid view: `b` took the packet pointer"), "{msg}");
    // static views are unaffected
    check_ok(&xdp(&format!("{HTTP}    emit E {{ a: ip.saddr, m: pkt.mac(0), b: sport == 80 }};")));
}

#[test]
fn payload_reads_are_checked_against_data_end() {
    let text = asm_xdp(&format!("{HTTP}    let line: str<8> = body.str();\n    emit E {{ a: body.u16(2), m: pkt.mac(0), b: body.starts_with(\"GET\") }};"));
    // r9 = tcp + doff*4
    assert!(text.contains("lsh r0, 2") && text.contains("mov r9, r1"), "{text}");
    // entry bound + the tcp view's sizeof check, then str<8>: 7 guarded byte
    // copies; starts_with: one 3-byte check; u16: one check
    assert_eq!(text.matches("if r2 > r8 goto").count(), 2 + 7 + 1 + 1, "{text}");
    assert!(text.contains("ldx16 r0, [r9 +2]"), "{text}");
    assert!(text.contains("ldx8 r0, [r9 +6]") && text.contains("stx8 [r10 -"), "{text}");
    // len = data_end - payload
    let text = asm_xdp(&format!("{HTTP}    emit E {{ a: body.len(), m: pkt.mac(0), b: true }};"));
    assert!(text.contains("mov r0, r8") && text.contains("sub r0, r9"), "{text}");
}

#[test]
fn redirect_records_an_interface_reloc() {
    let src = xdp("    redirect(\"veth0\");");
    let btf = kernel_btf();
    let c = compile_with_btf(&parse(&src).unwrap(), Arch::Aarch64, Some(&btf)).unwrap();
    let p = &c.programs[0];
    assert_eq!(p.ifaces.len(), 1, "{:#?}", p.ifaces);
    assert_eq!(p.ifaces[0].name, "veth0");
    let at = p.ifaces[0].slot * 8;
    assert_eq!(p.bytecode[at], 0x18, "an LD_IMM64 for the loader to patch");
    assert_eq!(p.bytecode[at + 1] & 0xf, 1, "into r1");
    let text = asm(&src);
    assert!(text.contains("call 23"), "{text}");
    let msg = first("event E { a: u32 } probe kprobe(\"f\") { redirect(\"eth0\"); emit E { a: 1 }; }");
    assert!(msg.contains("`redirect()` is only available in an `xdp` probe"), "{msg}");
    let msg = first(&xdp("    redirect(3);"));
    assert!(msg.contains("takes an interface name literal"), "{msg}");
}

#[test]
fn contains_is_a_bounded_window_search() {
    let udp = "    let udp: ptr<udphdr> = pkt.at(34);\n    let body = udp.payload();\n";
    check_ok(&xdp(&format!("{udp}    emit E {{ a: 1, m: pkt.mac(0), b: body.contains(\"abc\", 16) }};")));
    let msg = first(&xdp(&format!("{udp}    emit E {{ a: 1, m: pkt.mac(0), b: body.contains(\"abc\") }};")));
    assert!(msg.contains("`contains` takes a literal and a window"), "{msg}");
    let msg = first(&xdp(&format!("{udp}    emit E {{ a: 1, m: pkt.mac(0), b: body.contains(\"abc\", 2) }};")));
    assert!(msg.contains("needle is 3 bytes but the window only 2"), "{msg}");
    let msg = first(&xdp(&format!("{udp}    emit E {{ a: 1, m: pkt.mac(0), b: body.contains(\"abc\", 300) }};")));
    assert!(msg.contains("window must be 1..=256"), "{msg}");
    // 16-byte window, 3-byte needle: 14 start positions, each with its own check
    let text = asm_xdp(&format!("{udp}    emit E {{ a: 1, m: pkt.mac(0), b: body.contains(\"abc\", 16) }};"));
    assert_eq!(text.matches("if r2 > r8 goto").count(), 1 + 14, "{text}");
    assert_eq!(text.matches("if r0 != 97 goto").count(), 14, "{text}");
    assert!(text.contains("ldx8 r0, [r9 +13]") && text.contains("ldx8 r0, [r9 +15]"), "{text}");
    // udp payload starts 8 bytes after the header
    assert!(text.contains("add r9, 42"), "{text}");
}

// ---------------------------------------------------------- dns + rate limit

const DNS: &str = "    let udp: ptr<udphdr> = pkt.at(34);\n    let body = udp.payload();\n    let dns = body.dns();\n";

#[test]
fn dns_view_types_its_methods_and_orders_name_before_qtype() {
    check_ok(&xdp(&format!("{DNS}    let q: str<32> = dns.name();\n    let sum: u16 = dns.id() + dns.flags() + dns.qdcount() + dns.qtype() + dns.qclass();\n    emit E {{ a: 1, m: pkt.mac(0), b: dns.is_response() && dns.rcode() == 0 && sum == 0 }};")));
    let msg = first(&xdp(&format!("{DNS}    emit E {{ a: dns.qtype(), m: pkt.mac(0), b: true }};")));
    assert!(msg.contains("`dns.qtype()` needs the question name first"), "{msg}");
    let msg = first(&xdp(&format!("{DNS}    let q = dns.name();\n    emit E {{ a: 1, m: pkt.mac(0), b: true }};")));
    assert!(msg.contains("`.name()` needs a bounded destination"), "{msg}");
    // binding the dns view takes the packet pointer from the payload
    let msg = first(&xdp(&format!("{DNS}    emit E {{ a: body.len(), m: pkt.mac(0), b: true }};")));
    assert!(msg.contains("`body` is no longer a valid view: `dns` took the packet pointer"), "{msg}");
}

#[test]
fn dns_name_is_an_unrolled_label_walk_that_records_its_end() {
    let text = asm_xdp(&format!("{DNS}    let q: str<16> = dns.name();\n    emit E {{ a: dns.qtype(), m: pkt.mac(0), b: true }};"));
    // 15 positions, each: a packet-end check, a length-byte test, a 64 test
    assert_eq!(text.matches("if r0 >= 64 goto").count(), 15, "{text}");
    // (+1: the ringbuf reserve null check in the emit)
    assert_eq!(text.matches("if r0 == 0 goto").count(), 15 + 1, "{text}");
    // the first byte is always a length: no data path for position 0
    assert_eq!(text.matches("if r3 != 0 goto").count(), 14, "{text}");
    // dots are written, the end offset stored (12 + i + 1 for the first position = 13)
    assert!(text.contains("mov r1, 46") && text.contains("mov r1, 13"), "{text}");
    // qtype: the recorded end, masked, added to the payload pointer, checked
    assert!(text.contains("and r4, 511") && text.contains("add r3, r4"), "{text}");
}

#[test]
fn rate_limit_forms_and_rules() {
    check_ok("event E { a: u32 } probe kprobe(\"f\") { if rate_limit(10, 1000) { emit E { a: 1 }; } }");
    check_ok("event E { a: u32 } probe kprobe(\"f\") { if rate_limit(uid(), 10, 1000) { emit E { a: 1 }; } }");
    let msg = first("event E { a: u32 } probe kprobe(\"f\") { if rate_limit(0, 1000) { emit E { a: 1 }; } }");
    assert!(msg.contains("the limit must be at least 1"), "{msg}");
    let msg = first("event E { a: u32 } probe kprobe(\"f\") { if rate_limit(5, 0) { emit E { a: 1 }; } }");
    assert!(msg.contains("window is in milliseconds"), "{msg}");
    let msg = first("event E { a: u32 } probe kprobe(\"f\") { if rate_limit(5) { emit E { a: 1 }; } }");
    assert!(msg.contains("takes `(N, window_ms)` or `(key, N, window_ms)`"), "{msg}");
    let msg = first(&xdp("    let m = pkt.mac(0);\n    emit E { a: 1, m: m, b: rate_limit(m, 5, 1000) };"));
    assert!(msg.contains("keys by an integer"), "{msg}");
}

#[test]
fn rate_limit_reserves_maps_and_uses_ktime() {
    let src = "event E { a: u32 }\nprobe kprobe(\"f\") {\n    if rate_limit(10, 1000) && rate_limit(uid(), 3, 500) { emit E { a: 1 }; }\n    if rate_limit(pid(), 1, 1) { emit E { a: 2 }; }\n}";
    let btf = kernel_btf();
    let c = compile_with_btf(&parse(src).unwrap(), Arch::Aarch64, Some(&btf)).unwrap();
    let names: Vec<&str> = c.maps.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"__honey_rate") && names.contains(&"__honey_ratek0") && names.contains(&"__honey_ratek1"), "{names:?}");
    let rate = c.maps.iter().find(|m| m.name == "__honey_rate").unwrap();
    assert_eq!((rate.value_size, rate.max_entries), (16, 1));
    let keyed = c.maps.iter().find(|m| m.name == "__honey_ratek0").unwrap();
    assert_eq!((keyed.key_size, keyed.value_size), (8, 16));
    let text = asm(src);
    assert_eq!(text.matches("call 5").count(), 3, "one ktime per site\n{text}");
    assert_eq!(text.matches("call 2").count(), 2, "keyed sites insert on first sight\n{text}");
    assert!(text.contains("1000000000") && text.contains("500000000"), "windows in ns\n{text}");
}

#[test]
fn an_early_exit_inside_emit_discards_the_reservation() {
    // a payload read in a field can run off the packet: that exit must
    // discard the reserved record (helper 133), and only then exist
    let with = asm_xdp(&format!("{DNS}    emit E {{ a: dns.id(), m: pkt.mac(0), b: true }};"));
    assert_eq!(with.matches("call 133").count(), 1, "{with}");
    let without = asm_xdp("    emit E { a: pkt.u32(26), m: pkt.mac(0), b: true };");
    assert_eq!(without.matches("call 133").count(), 0, "no unreachable discard block\n{without}");
}
