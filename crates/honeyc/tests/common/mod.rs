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
