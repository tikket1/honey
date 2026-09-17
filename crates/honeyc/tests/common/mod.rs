//! Shared helpers for integration tests.
#![allow(dead_code)]

use honeyc::btf::Btf;

/// Build a small synthetic kernel BTF covering the structs the field-access
/// tests use: file, path, dentry, qstr — with realistic offsets. Hand-encoded
/// so the tests need no real kernel.
pub fn kernel_btf() -> Btf {
    let mut types: Vec<u8> = Vec::new();
    let push = |v: &mut Vec<u8>, name_off: u32, info: u32, sot: u32| {
        v.extend_from_slice(&name_off.to_le_bytes());
        v.extend_from_slice(&info.to_le_bytes());
        v.extend_from_slice(&sot.to_le_bytes());
    };
    let member = |v: &mut Vec<u8>, name_off: u32, type_id: u32, byte_off: u32| {
        v.extend_from_slice(&name_off.to_le_bytes());
        v.extend_from_slice(&type_id.to_le_bytes());
        v.extend_from_slice(&(byte_off * 8).to_le_bytes());
    };
    let info = |kind: u32, vlen: u32| (kind << 24) | vlen;
    const INT: u32 = 1;
    const PTR: u32 = 2;
    const STRUCT: u32 = 4;

    let mut strs = vec![0u8];
    let soff = |s: &str, strs: &mut Vec<u8>| -> u32 {
        let off = strs.len() as u32;
        strs.extend_from_slice(s.as_bytes());
        strs.push(0);
        off
    };
    let s = |name: &str, strs: &mut Vec<u8>| soff(name, strs);
    let s_u32 = s("u32", &mut strs);
    let s_uint = s("unsigned int", &mut strs);
    let s_char = s("char", &mut strs);
    let s_file = s("file", &mut strs);
    let s_be16 = s("__be16", &mut strs);
    let s_be32 = s("__be32", &mut strs);
    let s_u8 = s("__u8", &mut strs);
    let s_ethhdr = s("ethhdr", &mut strs);
    let s_hdest = s("h_dest", &mut strs);
    let s_hsource = s("h_source", &mut strs);
    let s_hproto = s("h_proto", &mut strs);
    let s_iphdr = s("iphdr", &mut strs);
    let s_ihl = s("ihl", &mut strs);
    let s_ttl = s("ttl", &mut strs);
    let s_protocol = s("protocol", &mut strs);
    let s_saddr = s("saddr", &mut strs);
    let s_daddr = s("daddr", &mut strs);
    let s_tcphdr = s("tcphdr", &mut strs);
    let s_check = s("check", &mut strs);
    let s_doff = s("doff", &mut strs);
    let s_sum16 = s("__sum16", &mut strs);
    let s_frame = s("frame", &mut strs);
    let s_icmphdr = s("icmphdr", &mut strs);
    let s_type = s("type", &mut strs);
    let s_un = s("un", &mut strs);
    let s_echo = s("echo", &mut strs);
    let s_id = s("id", &mut strs);
    let s_sequence = s("sequence", &mut strs);
    let s_eth = s("eth", &mut strs);
    let s_ip = s("ip", &mut strs);
    let s_source = s("source", &mut strs);
    let s_dest = s("dest", &mut strs);
    let s_path = s("path", &mut strs);
    let s_dentry = s("dentry", &mut strs);
    let s_qstr = s("qstr", &mut strs);
    let s_fflags = s("f_flags", &mut strs);
    let s_fpath = s("f_path", &mut strs);
    let s_dentryf = s("dentry", &mut strs);
    let s_dname = s("d_name", &mut strs);
    let s_name = s("name", &mut strs);

    // [1] INT u32; [2] INT char(size1); [3] PTR->char; [4] struct qstr{name@8};
    // [5] PTR->dentry(6); [6] struct dentry{d_name: qstr@32}; [7] struct path
    // {dentry: ptr->dentry @8}; [8] PTR->path(7); [9] struct file{f_flags:u32
    // @48, f_path: path @64}
    push(&mut types, s_u32, info(INT, 0), 4);
    types.extend_from_slice(&0u32.to_le_bytes());
    push(&mut types, s_char, info(INT, 0), 1);
    types.extend_from_slice(&(2u32 << 24).to_le_bytes());
    push(&mut types, 0, info(PTR, 0), 2); // [3]
    push(&mut types, s_qstr, info(STRUCT, 1), 16); // [4]
    member(&mut types, s_name, 3, 8);
    push(&mut types, 0, info(PTR, 0), 6); // [5]
    push(&mut types, s_dentry, info(STRUCT, 1), 192); // [6]
    member(&mut types, s_dname, 4, 32);
    push(&mut types, s_path, info(STRUCT, 1), 16); // [7]
    member(&mut types, s_dentryf, 5, 8);
    push(&mut types, 0, info(PTR, 0), 7); // [8]
    push(&mut types, s_file, info(STRUCT, 2), 256); // [9]
    member(&mut types, s_fflags, 1, 48);
    member(&mut types, s_fpath, 7, 64);
    let _ = (s_uint, s_u32);

    // Network headers.
    // [10] INT u16 (2 bytes); [11] TYPEDEF __be16 -> 10; [12] TYPEDEF __be32 -> 1 (u32)
    // [13] INT u8 (1) named __u8-ish; [14] ARRAY of [13] x 6
    // [15] struct ethhdr { h_dest: [14]@0, h_source: [14]@6, h_proto: be16 @12 } size 14
    // [16] anonymous struct { saddr: be32 @0, daddr: be32 @4 } size 8
    // [17] struct iphdr (kind_flag) { ihl: bitfield 4 bits @0, ttl: u8 @8, protocol: u8 @9, check: __sum16 @10, <anon>: [16] @12 } size 20
    const TYPEDEF: u32 = 8;
    const ARRAY: u32 = 3;
    push(&mut types, 0, info(INT, 0), 2);
    types.extend_from_slice(&0u32.to_le_bytes()); // [10]
    push(&mut types, s_be16, info(TYPEDEF, 0), 10); // [11]
    push(&mut types, s_be32, info(TYPEDEF, 0), 1); // [12]
    push(&mut types, s_u8, info(INT, 0), 1);
    types.extend_from_slice(&0u32.to_le_bytes()); // [13]
    push(&mut types, 0, info(ARRAY, 0), 0); // [14]: btf_array { type=13, index_type=1, nelems=6 }
    types.extend_from_slice(&13u32.to_le_bytes());
    types.extend_from_slice(&1u32.to_le_bytes());
    types.extend_from_slice(&6u32.to_le_bytes());
    push(&mut types, s_ethhdr, info(STRUCT, 3), 14); // [15]
    member(&mut types, s_hdest, 14, 0);
    member(&mut types, s_hsource, 14, 6);
    member(&mut types, s_hproto, 11, 12);
    push(&mut types, 0, info(STRUCT, 2), 8); // [16] anonymous
    member(&mut types, s_saddr, 12, 0);
    member(&mut types, s_daddr, 12, 4);
    // [17] iphdr with kind_flag: member offsets are (bitfield_size << 24) | bit_offset
    let kflag_info = |kind: u32, vlen: u32| (1u32 << 31) | (kind << 24) | vlen;
    push(&mut types, s_iphdr, kflag_info(STRUCT, 5), 20);
    // ihl: 4-bit bitfield at bit 0
    types.extend_from_slice(&s_ihl.to_le_bytes());
    types.extend_from_slice(&13u32.to_le_bytes());
    types.extend_from_slice(&(4u32 << 24).to_le_bytes());
    member(&mut types, s_ttl, 13, 8);
    member(&mut types, s_protocol, 13, 9);
    member(&mut types, s_check, 19, 10);
    member(&mut types, 0, 16, 12); // anonymous union/struct holding saddr/daddr
    // [18] struct tcphdr (kind_flag) { source: be16 @0, dest: be16 @2, doff: 4 bits @ bit 100, check: __sum16 @16 } size 20
    push(&mut types, s_tcphdr, kflag_info(STRUCT, 4), 20);
    member(&mut types, s_source, 11, 0);
    member(&mut types, s_dest, 11, 2);
    types.extend_from_slice(&s_doff.to_le_bytes());
    types.extend_from_slice(&10u32.to_le_bytes());
    types.extend_from_slice(&((4u32 << 24) | 100).to_le_bytes());
    member(&mut types, s_check, 19, 16);
    // [19] TYPEDEF __sum16 -> 10: a checksum, read swapped like __be16
    push(&mut types, s_sum16, info(TYPEDEF, 0), 10);
    // [20] struct frame { eth: ethhdr @0, ip: iphdr @14 } size 34: named embedded structs
    push(&mut types, s_frame, info(STRUCT, 2), 34);
    member(&mut types, s_eth, 15, 0);
    member(&mut types, s_ip, 17, 14);
    // [21] struct icmphdr { type: u8 @0, checksum: __sum16 @2, un: [22] @4 } size 8
    // [22] anonymous union { echo: [23] @0 }  [23] anonymous struct { id: be16 @0, sequence: be16 @2 }
    // — named members of anonymous types, exactly like the kernel's icmphdr.
    const UNION: u32 = 5;
    push(&mut types, s_icmphdr, info(STRUCT, 3), 8);
    member(&mut types, s_type, 13, 0);
    member(&mut types, s_check, 19, 2);
    member(&mut types, s_un, 22, 4);
    push(&mut types, 0, info(UNION, 1), 4);
    member(&mut types, s_echo, 23, 0);
    push(&mut types, 0, info(STRUCT, 2), 4);
    member(&mut types, s_id, 11, 0);
    member(&mut types, s_sequence, 11, 2);

    let hdr_len = 24u32;
    let type_len = types.len() as u32;
    let str_len = strs.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&0xeb9fu16.to_le_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(&hdr_len.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&type_len.to_le_bytes());
    out.extend_from_slice(&type_len.to_le_bytes());
    out.extend_from_slice(&str_len.to_le_bytes());
    out.extend_from_slice(&types);
    out.extend_from_slice(&strs);
    Btf::parse(&out).expect("synthetic BTF parses")
}
