//! A minimal reader for the kernel's BTF (BPF Type Format).
//!
//! BTF is the type information the kernel ships at `/sys/kernel/btf/vmlinux`.
//! honey reads it at compile time to answer two questions about a kernel
//! struct field like `file.f_path`:
//!
//! - does the field exist, and what is its type? (for the checker)
//! - what is its byte offset, and is it an embedded struct, a pointer, or a
//!   scalar? (for codegen)
//!
//! We only parse what those questions need: the type table, the string table,
//! and struct/union members. Every other type kind is skipped over (correctly,
//! so the table stays aligned) but not interpreted.
//!
//! The binary format (see the kernel's `Documentation/bpf/btf.rst`): a header,
//! then a type section, then a string section. Each type has a 12-byte common
//! part (`name_off`, `info`, `size_or_type`) followed by kind-specific data.
//! `info` packs `vlen` (low 16 bits), `kind` (bits 24..28), and a `kind_flag`
//! (bit 31). All little-endian.

use std::collections::HashMap;

const MAGIC: u16 = 0xeb9f;

// BTF kind numbers.
const INT: u32 = 1;
const PTR: u32 = 2;
const ARRAY: u32 = 3;
const STRUCT: u32 = 4;
const UNION: u32 = 5;
const ENUM: u32 = 6;
const TYPEDEF: u32 = 8;
const VOLATILE: u32 = 9;
const CONST: u32 = 10;
const RESTRICT: u32 = 11;
const FUNC_PROTO: u32 = 13;
const VAR: u32 = 14;
const DATASEC: u32 = 15;
const DECL_TAG: u32 = 17;
const ENUM64: u32 = 19;

/// A parsed BTF type (only the fields honey uses).
#[derive(Debug, Clone)]
struct BtfType {
    name: String,
    kind: u32,
    /// For INT/STRUCT/UNION/ENUM: the size in bytes. For PTR/TYPEDEF/CONST/
    /// VOLATILE/RESTRICT: the referenced type id.
    size_or_type: u32,
    /// Signed flag, for INT only.
    int_signed: bool,
    members: Vec<Member>,
    /// For ARRAY: (element type id, element count).
    array: Option<(u32, u32)>,
}

/// A struct/union member, as honey needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub offset_bytes: u32,
    pub type_id: u32,
    /// Bit offset from the start of the struct (little-endian numbering).
    pub bit_offset: u32,
    /// Width in bits for a bitfield member, 0 otherwise.
    pub bit_size: u32,
}

impl Member {
    pub fn bitfield(&self) -> bool {
        self.bit_size > 0
    }
}

type MemberVec = Vec<Member>;

/// A loaded BTF blob, indexed by type id (1-based; id 0 is the void type).
pub struct Btf {
    types: Vec<BtfType>,
    struct_by_name: HashMap<String, u32>,
}

/// What a field's type resolves to, after stripping typedef/const/volatile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// An integer of `bytes` width. `big_endian` when the field was declared
    /// through a `__be16`/`__be32`/`__be64` typedef (network byte order).
    Int { bytes: u32, signed: bool, big_endian: bool },
    /// An array of `len` elements of `elem_bytes` each (only byte arrays are
    /// useful to honey: MACs and raw addresses).
    Array { elem_bytes: u32, len: u32 },
    /// An embedded struct/union: its address is `base + offset`, no read.
    /// `name` is empty for an anonymous type; `id` always identifies it.
    Struct { id: u32, name: String },
    /// A pointer to a named struct: read 8 bytes to get that struct's address.
    PtrToStruct { id: u32, name: String },
    /// A pointer to a `char`: read 8 bytes to get a string address.
    PtrToChar,
    /// A pointer to anything else: read 8 bytes to get an address.
    PtrToOther,
    /// Anything honey does not model (enums, arrays, function pointers, ...).
    Other,
}

impl Btf {
    pub fn load(path: &str) -> Result<Btf, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        Btf::parse(&bytes).map_err(|e| format!("{path}: {e}"))
    }

    pub fn parse(b: &[u8]) -> Result<Btf, String> {
        if b.len() < 24 {
            return Err("BTF too short".into());
        }
        let u16le = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32le = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        if u16le(0) != MAGIC {
            return Err(format!("bad BTF magic {:#06x}", u16le(0)));
        }
        let hdr_len = u32le(4) as usize;
        let type_off = u32le(8) as usize;
        let type_len = u32le(12) as usize;
        let str_off = u32le(16) as usize;
        let str_len = u32le(20) as usize;

        let type_start = hdr_len + type_off;
        let type_end = type_start + type_len;
        let str_start = hdr_len + str_off;
        let str_end = str_start + str_len;
        if type_end > b.len() || str_end > b.len() {
            return Err("BTF sections out of bounds".into());
        }
        let strings = &b[str_start..str_end];
        let name_of = |off: u32| -> String {
            let off = off as usize;
            if off >= strings.len() {
                return String::new();
            }
            let end = strings[off..].iter().position(|&c| c == 0).map_or(strings.len(), |p| off + p);
            String::from_utf8_lossy(&strings[off..end]).into_owned()
        };

        // Type id 0 is the implicit void type.
        let mut types =
            vec![BtfType { name: String::new(), kind: 0, size_or_type: 0, int_signed: false, members: Vec::new(), array: None }];
        let mut struct_by_name = HashMap::new();

        let mut p = type_start;
        while p + 12 <= type_end {
            let name_off = u32le(p);
            let info = u32le(p + 4);
            let size_or_type = u32le(p + 8);
            p += 12;

            let vlen = (info & 0xffff) as usize;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = (info >> 31) & 1;

            let name = name_of(name_off);
            let mut int_signed = false;
            let mut members = Vec::new();
            let mut array = None;

            // Skip or read the kind-specific trailing data.
            match kind {
                INT => {
                    let enc = u32le(p);
                    // bits 24..28 hold the encoding; bit 0 (value 1) = signed.
                    int_signed = ((enc >> 24) & 0x1) == 1;
                    p += 4;
                }
                STRUCT | UNION => {
                    for _ in 0..vlen {
                        let mn = u32le(p);
                        let mt = u32le(p + 4);
                        let moff = u32le(p + 8);
                        p += 12;
                        // With kind_flag, `moff` packs a bitfield; the low 24
                        // bits are still the bit offset. honey's structs are
                        // byte-aligned, so bit offset / 8 is the byte offset.
                        let bit_off = if kind_flag == 1 { moff & 0xffffff } else { moff };
                        let bit_size = if kind_flag == 1 { moff >> 24 } else { 0 };
                        members.push(Member { name: name_of(mn), offset_bytes: bit_off / 8, type_id: mt, bit_offset: bit_off, bit_size });
                    }
                }
                ENUM => p += vlen * 8,
                ENUM64 => p += vlen * 12,
                ARRAY => {
                    array = Some((u32le(p), u32le(p + 8)));
                    p += 12;
                }
                FUNC_PROTO => p += vlen * 8,
                DATASEC => p += vlen * 12,
                VAR => p += 4,
                DECL_TAG => p += 4,
                // PTR, TYPEDEF, CONST, VOLATILE, RESTRICT, FWD, FUNC, FLOAT,
                // TYPE_TAG: no trailing data.
                _ => {}
            }

            let id = types.len() as u32;
            if (kind == STRUCT || kind == UNION) && !name.is_empty() {
                struct_by_name.entry(name.clone()).or_insert(id);
            }
            types.push(BtfType { name, kind, size_or_type, int_signed, members, array });
        }

        Ok(Btf { types, struct_by_name })
    }

    /// The type id of a struct by name, if present.
    pub fn struct_id(&self, name: &str) -> Option<u32> {
        self.struct_by_name.get(name).copied()
    }

    pub fn is_struct(&self, name: &str) -> bool {
        self.struct_by_name.contains_key(name)
    }

    fn get(&self, id: u32) -> Option<&BtfType> {
        self.types.get(id as usize)
    }

    /// The members of a struct named `name`.
    pub fn members(&self, name: &str) -> Option<MemberVec> {
        let id = self.struct_id(name)?;
        Some(self.get(id)?.members.clone())
    }

    /// Find a member by name in a struct, looking through anonymous
    /// struct/union members (the kernel wraps `iphdr.saddr`/`daddr` in one).
    /// The returned offset is relative to the outer struct.
    pub fn member(&self, struct_name: &str, field: &str) -> Option<Member> {
        let id = self.struct_id(struct_name)?;
        self.member_in(id, field, 0)
    }

    /// `member`, by type id: the way to reach fields of anonymous
    /// structs/unions, which have no name to look up.
    pub fn member_of(&self, type_id: u32, field: &str) -> Option<Member> {
        self.member_in(type_id, field, 0)
    }

    /// Size in bytes of a struct/union by id (through typedefs).
    pub fn type_size(&self, type_id: u32) -> Option<u32> {
        let t = self.strip(type_id)?;
        (t.kind == STRUCT || t.kind == UNION).then_some(t.size_or_type)
    }

    /// The name of a struct/union by id: `Some("")` when it is anonymous.
    pub fn type_name(&self, type_id: u32) -> Option<String> {
        let t = self.strip(type_id)?;
        (t.kind == STRUCT || t.kind == UNION).then(|| t.name.clone())
    }

    fn member_in(&self, type_id: u32, field: &str, base: u32) -> Option<Member> {
        let t = self.strip(type_id)?;
        if t.kind != STRUCT && t.kind != UNION {
            return None;
        }
        if let Some(m) = t.members.iter().find(|m| m.name == field) {
            return Some(Member { offset_bytes: base + m.offset_bytes, bit_offset: base * 8 + m.bit_offset, ..m.clone() });
        }
        for m in t.members.iter().filter(|m| m.name.is_empty()) {
            if let Some(found) = self.member_in(m.type_id, field, base + m.offset_bytes) {
                return Some(found);
            }
        }
        None
    }

    /// Size in bytes of a named struct.
    pub fn struct_size(&self, name: &str) -> Option<u32> {
        let id = self.struct_id(name)?;
        Some(self.get(id)?.size_or_type)
    }

    /// Follow typedef/const/volatile/restrict until a concrete type.
    fn strip(&self, id: u32) -> Option<&BtfType> {
        self.strip_id(id).map(|(_, t)| t)
    }

    /// `strip`, also returning the id the chain ends at.
    fn strip_id(&self, mut id: u32) -> Option<(u32, &BtfType)> {
        for _ in 0..32 {
            let t = self.get(id)?;
            match t.kind {
                TYPEDEF | CONST | VOLATILE | RESTRICT => id = t.size_or_type,
                _ => return Some((id, t)),
            }
        }
        None
    }

    /// Does the typedef chain name a big-endian type (`__be16`, `__be32`, ...)?
    fn is_big_endian(&self, mut id: u32) -> bool {
        for _ in 0..32 {
            let Some(t) = self.get(id) else { return false };
            match t.kind {
                TYPEDEF => {
                    // `__sum16`/`__wsum` are checksums stored as they sit on
                    // the wire; reading them swapped keeps checksum arithmetic
                    // in the same byte order as every other header field.
                    if t.name.starts_with("__be")
                        || t.name.starts_with("be") && t.name.len() <= 4
                        || t.name == "__sum16"
                        || t.name == "__wsum"
                    {
                        return true;
                    }
                    id = t.size_or_type;
                }
                CONST | VOLATILE | RESTRICT => id = t.size_or_type,
                _ => return false,
            }
        }
        false
    }

    /// Resolve a member's type id into honey's field model.
    pub fn resolve(&self, type_id: u32) -> Resolved {
        let big_endian = self.is_big_endian(type_id);
        let Some((tid, t)) = self.strip_id(type_id) else { return Resolved::Other };
        match t.kind {
            INT => Resolved::Int { bytes: t.size_or_type.min(8), signed: t.int_signed, big_endian },
            ARRAY => {
                let Some((elem, n)) = t.array else { return Resolved::Other };
                let Some(et) = self.strip(elem) else { return Resolved::Other };
                if et.kind == INT { Resolved::Array { elem_bytes: et.size_or_type, len: n } } else { Resolved::Other }
            }
            STRUCT | UNION => Resolved::Struct { id: tid, name: t.name.clone() },
            PTR => {
                let Some((pid, pointee)) = self.strip_id(t.size_or_type) else { return Resolved::PtrToOther };
                match pointee.kind {
                    STRUCT | UNION if !pointee.name.is_empty() => Resolved::PtrToStruct { id: pid, name: pointee.name.clone() },
                    INT if pointee.size_or_type == 1 => Resolved::PtrToChar,
                    _ => Resolved::PtrToOther,
                }
            }
            _ => Resolved::Other,
        }
    }
}

// --------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a tiny BTF blob by hand, so the parser is tested without a real
    /// kernel. Types: [1] u32 int, [2] char int, [3] ptr->char, [4] struct
    /// qstr { name: ptr->char @8 }, [5] ptr->qstr, [6] struct dentry {
    /// d_name: qstr @32 (embedded), d_parent: ptr->dentry @24 }.
    fn sample() -> Vec<u8> {
        let mut types: Vec<u8> = Vec::new();
        let push = |v: &mut Vec<u8>, name_off: u32, info: u32, sot: u32| {
            v.extend_from_slice(&name_off.to_le_bytes());
            v.extend_from_slice(&info.to_le_bytes());
            v.extend_from_slice(&sot.to_le_bytes());
        };
        let kind = |k: u32, vlen: u32, flag: u32| (flag << 31) | (k << 24) | vlen;

        // string table: build offsets as we go
        let mut strs = vec![0u8]; // first byte is the empty string
        let soff = |s: &str, strs: &mut Vec<u8>| -> u32 {
            let off = strs.len() as u32;
            strs.extend_from_slice(s.as_bytes());
            strs.push(0);
            off
        };
        let s_u32 = soff("u32", &mut strs);
        let s_char = soff("char", &mut strs);
        let s_qstr = soff("qstr", &mut strs);
        let s_name = soff("name", &mut strs);
        let s_dentry = soff("dentry", &mut strs);
        let s_dname = soff("d_name", &mut strs);
        let s_dparent = soff("d_parent", &mut strs);

        // [1] INT u32 (size 4, unsigned)
        push(&mut types, s_u32, kind(INT, 0, 0), 4);
        types.extend_from_slice(&0u32.to_le_bytes()); // int encoding
        // [2] INT char (size 1)
        push(&mut types, s_char, kind(INT, 0, 0), 1);
        types.extend_from_slice(&(2u32 << 24).to_le_bytes()); // char encoding bit
        // [3] PTR -> char (type 2)
        push(&mut types, 0, kind(PTR, 0, 0), 2);
        // [4] STRUCT qstr { name: ptr(3) @ byte 8 }
        push(&mut types, s_qstr, kind(STRUCT, 1, 0), 16);
        types.extend_from_slice(&s_name.to_le_bytes());
        types.extend_from_slice(&3u32.to_le_bytes());
        types.extend_from_slice(&(8u32 * 8).to_le_bytes()); // bit offset
        // [5] PTR -> dentry (type 6, forward ref is fine by id)
        push(&mut types, 0, kind(PTR, 0, 0), 6);
        // [6] STRUCT dentry { d_name: qstr(4) @32, d_parent: ptr(5) @24 }
        push(&mut types, s_dentry, kind(STRUCT, 2, 0), 192);
        types.extend_from_slice(&s_dname.to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&(32u32 * 8).to_le_bytes());
        types.extend_from_slice(&s_dparent.to_le_bytes());
        types.extend_from_slice(&5u32.to_le_bytes());
        types.extend_from_slice(&(24u32 * 8).to_le_bytes());

        // header
        let hdr_len = 24u32;
        let type_len = types.len() as u32;
        let str_len = strs.len() as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.push(1); // version
        out.push(0); // flags
        out.extend_from_slice(&hdr_len.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off
        out.extend_from_slice(&type_len.to_le_bytes());
        out.extend_from_slice(&type_len.to_le_bytes()); // str_off = after types
        out.extend_from_slice(&str_len.to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strs);
        out
    }

    #[test]
    fn parses_structs_and_members() {
        let btf = Btf::parse(&sample()).unwrap();
        assert!(btf.is_struct("qstr"));
        assert!(btf.is_struct("dentry"));
        assert!(!btf.is_struct("nope"));

        let name = btf.member("qstr", "name").unwrap();
        assert_eq!(name.offset_bytes, 8);
        assert_eq!(btf.resolve(name.type_id), Resolved::PtrToChar);

        let dname = btf.member("dentry", "d_name").unwrap();
        assert_eq!(dname.offset_bytes, 32);
        assert_eq!(btf.resolve(dname.type_id), Resolved::Struct { id: 4, name: "qstr".into() });

        let dparent = btf.member("dentry", "d_parent").unwrap();
        assert_eq!(dparent.offset_bytes, 24);
        assert_eq!(btf.resolve(dparent.type_id), Resolved::PtrToStruct { id: 6, name: "dentry".into() });
        assert_eq!(btf.member_of(6, "d_name").map(|m| m.offset_bytes), Some(32));
        assert_eq!(btf.type_size(6), Some(192));
        assert_eq!(btf.type_name(4).as_deref(), Some("qstr"));
        assert_eq!(btf.struct_size("dentry"), Some(192));
        assert_eq!(btf.resolve(1), Resolved::Int { bytes: 4, signed: false, big_endian: false });
    }

    #[test]
    fn unknown_member_is_none() {
        let btf = Btf::parse(&sample()).unwrap();
        assert!(btf.member("qstr", "missing").is_none());
        assert!(btf.member("nostruct", "x").is_none());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = sample();
        b[0] = 0;
        assert!(Btf::parse(&b).is_err());
    }
}
