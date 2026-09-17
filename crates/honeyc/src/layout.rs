//! Event record layout: turning an `event` declaration into a byte layout
//! that both the BPF program (which writes the record) and the C loader
//! (which reads it) agree on.
//!
//! Rules: fields are placed in declaration order, each aligned up to its own
//! alignment, and the whole record is rounded up to its largest alignment.
//! This matches what a C compiler would do for the equivalent struct, so the
//! loader can treat the ring-buffer bytes as a packed C struct.

use crate::ast::{EventDecl, TypeArg};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLayout {
    pub name: String,
    pub fields: Vec<FieldLayout>,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLayout {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub kind: FieldKind,
}

/// What a field holds, as far as codegen and the loader care.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    /// An unsigned integer of the given byte width (1, 2, 4, 8).
    Uint(u32),
    /// A fixed-capacity string of `N` bytes.
    Str(u32),
    Bool,
}

impl FieldKind {
    fn align(&self) -> u32 {
        match self {
            FieldKind::Uint(w) => *w,
            FieldKind::Str(_) => 1,
            FieldKind::Bool => 1,
        }
    }

    fn size(&self) -> u32 {
        match self {
            FieldKind::Uint(w) => *w,
            FieldKind::Str(n) => *n,
            FieldKind::Bool => 1,
        }
    }
}

/// Compute the layout of an event, or return a human error for an
/// unsupported field type.
pub fn layout_event(ev: &EventDecl) -> Result<EventLayout, String> {
    let mut fields = Vec::new();
    let mut offset = 0u32;
    let mut max_align = 1u32;

    for f in &ev.fields {
        let kind = field_kind(&f.ty.name.name, &f.ty.args)
            .ok_or_else(|| format!("unsupported field type `{}` in event `{}`", f.ty.name.name, ev.name.name))?;
        let align = kind.align();
        max_align = max_align.max(align);
        offset = round_up(offset, align);
        let size = kind.size();
        fields.push(FieldLayout { name: f.name.name.clone(), offset, size, kind });
        offset += size;
    }

    let size = round_up(offset, max_align);
    Ok(EventLayout { name: ev.name.name.clone(), fields, size })
}

fn field_kind(name: &str, args: &[TypeArg]) -> Option<FieldKind> {
    match name {
        "u8" => Some(FieldKind::Uint(1)),
        "u16" => Some(FieldKind::Uint(2)),
        "u32" => Some(FieldKind::Uint(4)),
        "u64" => Some(FieldKind::Uint(8)),
        "bool" => Some(FieldKind::Bool),
        "str" => match args {
            [TypeArg::Int(n)] => Some(FieldKind::Str(*n as u32)),
            _ => None,
        },
        _ => None,
    }
}

fn round_up(value: u32, align: u32) -> u32 {
    value.div_ceil(align) * align
}
