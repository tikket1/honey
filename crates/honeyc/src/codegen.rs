//! Stage 3 codegen: compile honey probes to BPF bytecode.
//!
//! A program may contain several probes. Each becomes its own BPF program
//! (its own instruction stream and 512-byte stack); they share the maps and
//! the event ring buffer. Probe kinds:
//!
//! | kind                        | BPF program type | context (R1 at entry)    |
//! |-----------------------------|------------------|--------------------------|
//! | `tracepoint("cat", "name")` | TRACEPOINT       | tracepoint record; `arg(n)` at `+16 + 8n` |
//! | `kprobe("fn")`              | KPROBE           | `struct pt_regs`; `arg(n)` per arch |
//! | `kretprobe("fn")`           | KPROBE (retprobe)| `struct pt_regs`; `retval()` per arch |
//!
//! `pt_regs` layout differs per architecture, so codegen takes an [`Arch`].
//!
//! # Records
//!
//! Every emitted record starts with an 8-byte header holding the event id
//! (`u32`) so a single ring buffer can carry several event types; the loader
//! dispatches on it. Field offsets from `layout.rs` are relative to the
//! payload that follows the header.
//!
//! # How values move
//!
//! Every expression evaluates into `R0`. Locals are 8-byte stack slots
//! (`str<N>` buffers are N rounded to 8) at `[R10 - off]`, allocated per
//! scope and released LIFO. Binary operators spill the left operand to a
//! scratch slot while the right is computed, then reload it into `R1`.
//! `R6` holds the ring-buffer record during an `emit`; helper calls preserve
//! it. The context pointer is spilled in the prologue so `arg`/`retval` can
//! read it after `R1` has been reused.
//!
//! `map.get` spills its result and *then* null-checks it: the verifier
//! propagates the check to the spilled copy, so reloading it inside the
//! `if let` body yields a pointer it will let you dereference. The type
//! checker (stage 4) guarantees the program only ever does that.
//!
//! # Map references
//!
//! `ld64 rN, map_fd(i)` carries a map *index*: 0 is the event ring buffer,
//! user maps follow in declaration order. The loader creates the maps and
//! rewrites each index to the fd it got.

use std::collections::HashMap;

use crate::addr;
use crate::ast::*;
use crate::bpf::{self, *};
use crate::btf::{Btf, Resolved};
use crate::layout::{layout_event, EventLayout, FieldKind};

// ------------------------------------------------------------------ output

/// Target architecture: decides `pt_regs` offsets for kprobes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    pub fn parse(s: &str) -> Option<Arch> {
        match s {
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            "x86_64" | "amd64" => Some(Arch::X86_64),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        }
    }

    /// Byte offset in `struct pt_regs` of the n-th integer argument.
    fn kprobe_arg_offset(self, n: i64) -> Option<i16> {
        match self {
            // regs[0..8] = x0..x7, contiguous.
            Arch::Aarch64 => (0..8).contains(&n).then(|| (8 * n) as i16),
            // rdi, rsi, rdx, rcx, r8, r9.
            Arch::X86_64 => [112, 104, 96, 88, 72, 64].get(n as usize).copied(),
        }
    }

    /// Byte offset in `struct pt_regs` of the return value register.
    fn retval_offset(self) -> i16 {
        match self {
            Arch::Aarch64 => 0,  // x0
            Arch::X86_64 => 80, // rax
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeKind {
    Tracepoint { category: String, name: String },
    Kprobe { function: String },
    Kretprobe { function: String },
    /// An LSM hook. The program returns 0 to allow, negative to deny.
    Lsm { hook: String },
    /// An XDP program on a network interface. Returns an XDP action.
    Xdp { interface: String },
    /// A uprobe on a userspace function entry (`path:symbol`).
    Uprobe { target: String },
    /// A uretprobe on a userspace function return (`path:symbol`).
    Uretprobe { target: String },
    /// A USDT marker in a user binary (`path:provider:name`).
    Usdt { target: String },
}

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

/// USDT argument spec, one per probe program, filled in by the loader from
/// the marker's note. Six args of 16 bytes:
///   +0 kind (0 none, 1 register, 2 memory via register, 3 constant)
///   +1 signed (0/1)          +2 shift (64 - 8*size, to extract the low bytes)
///   +4 reg_off (u16, byte offset of the register in pt_regs)
///   +8 val (i64: memory offset for kind 2, the value for kind 3)
pub const USDT_ARG_SIZE: u32 = 16;
pub const USDT_MAX_ARGS: u32 = 6;
pub const USDT_SPEC_SIZE: u32 = USDT_ARG_SIZE * USDT_MAX_ARGS;
const USDT_KIND_NONE: i32 = 0;
const USDT_KIND_MEM: i32 = 2;
const USDT_KIND_CONST: i32 = 3;

/// A field-offset relocation: instruction slot `slot` carries the byte
/// offset of `struct_name.field`, resolved at compile time from BTF. The
/// loader re-resolves it against the running kernel and rewrites the imm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    pub slot: usize,
    pub struct_name: String,
    pub field: String,
}

/// One BPF program.
#[derive(Debug, Clone)]
pub struct CompiledProbe {
    /// `tracepoint:syscalls:sys_enter_execve`, `kprobe:do_sys_openat2`, ...
    pub name: String,
    pub kind: ProbeKind,
    pub bytecode: Vec<u8>,
    pub stack_bytes: u32,
    pub relocs: Vec<Reloc>,
}

/// Everything the loader needs to install a honey program.
#[derive(Debug, Clone)]
pub struct Compiled {
    pub programs: Vec<CompiledProbe>,
    /// Ring buffer size in bytes (map index 0).
    pub ringbuf_bytes: u32,
    /// User maps, in index order starting at 1.
    pub maps: Vec<MapSpec>,
    /// Every declared event; its position is its id in the record header.
    pub events: Vec<EventLayout>,
    pub license: String,
    pub arch: Arch,
    /// Largest per-probe stack use.
    pub stack_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSpec {
    pub name: String,
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Hash,
    Array,
}

const RINGBUF_INDEX: i32 = 0;
const BPF_STACK_LIMIT: i32 = 512;
/// Bytes before the payload in every ring-buffer record: `u32` event id + pad.
pub const RECORD_HEADER: u32 = 8;

// -------------------------------------------------------------------- types
//
// Just enough type information to pick load/store widths and signedness.
// The type checker (stage 4) has already validated the program.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ty {
    Uint(u32),
    I64,
    Bool,
    Str(u32),
    /// Byte blobs copied from the packet: a 16-byte IPv6 or 6-byte MAC.
    Ipv6,
    Mac,
    ValuePtr(Box<Ty>),
    OptionPtr(Box<Ty>),
    /// Kernel pointer to a named struct (an address).
    KPtr(String),
    /// Kernel pointer to char (a string address).
    KCharPtr,
    /// A packet struct view: `struct name` at this constant packet offset.
    /// Never stored; every field read is `[R7 + off + field]`.
    PktPtr(String, i16),
}

impl Ty {
    fn from_ast(t: &Type) -> Result<Ty, String> {
        match (t.name.name.as_str(), t.args.as_slice()) {
            ("u8", []) => Ok(Ty::Uint(1)),
            ("u16", []) => Ok(Ty::Uint(2)),
            ("u32", []) => Ok(Ty::Uint(4)),
            ("u64", []) => Ok(Ty::Uint(8)),
            ("i64", []) => Ok(Ty::I64),
            ("ipv4", []) => Ok(Ty::Uint(4)),
            ("ipv6", []) => Ok(Ty::Ipv6),
            ("mac", []) => Ok(Ty::Mac),
            ("bool", []) => Ok(Ty::Bool),
            ("ptr", [TypeArg::Type(inner)]) => Ok(Ty::KPtr(inner.name.name.clone())),
            (other, _) => Err(format!("type `{other}` is not supported in codegen")),
        }
    }

    fn size(&self) -> u32 {
        match self {
            Ty::Uint(w) => *w,
            Ty::Bool => 1,
            Ty::Str(n) => *n,
            Ty::Ipv6 => 16,
            Ty::Mac => 6,
            Ty::I64 | Ty::ValuePtr(_) | Ty::OptionPtr(_) | Ty::KPtr(_) | Ty::KCharPtr => 8,
            Ty::PktPtr(..) => 0,
        }
    }

    fn mem_size(&self) -> Size {
        match self.size() {
            1 => Size::B,
            2 => Size::H,
            4 => Size::W,
            _ => Size::DW,
        }
    }
}

// ------------------------------------------------------------------- frame

#[derive(Debug, Clone)]
struct Local {
    /// Stack offset below R10 (unused when `reg` is set).
    off: i16,
    ty: Ty,
    /// The callee-saved register holding this scalar, if it got one.
    reg: Option<Reg>,
}

/// Declarations shared by every probe in the program.
struct Shared<'a> {
    events: Vec<EventLayout>,
    event_ids: HashMap<String, u32>,
    maps: Vec<MapSpec>,
    map_index: HashMap<String, i32>,
    map_types: HashMap<String, (Ty, Ty)>,
    consts: HashMap<String, i64>,
    arch: Arch,
    btf: Option<&'a Btf>,
    /// Map index of the hidden sampling counter array, if any `sample()` used.
    sample_map: Option<i32>,
    /// Map index of the hidden USDT argument-spec array, if any usdt probe.
    usdt_map: Option<i32>,
}


struct Cg<'a> {
    sh: &'a Shared<'a>,
    kind: &'a ProbeKind,
    prog: Prog,
    scopes: Vec<HashMap<String, Local>>,
    /// Loop variables and other per-probe constants (shadow `sh.consts`).
    local_consts: HashMap<String, i64>,
    stack_top: i32,
    max_stack: i32,
    exit_label: Label,
    ctx_slot: i16,
    /// (instruction index, struct, field) field-offset relocations.
    relocs: Vec<(usize, String, String)>,
    /// Running counter that assigns each `sample()` site its map slot.
    sample_next: &'a mut u32,
    /// This program's index in the manifest (key into the USDT spec map).
    prog_index: u32,
    /// Callee-saved registers free for locals and temporaries. R6 is
    /// reserved when the probe emits (record pointer), R7/R8 in XDP (packet
    /// bounds), R9 in USDT (arg spec); the rest are ours. Registers survive
    /// helper calls, so a value parked here needs no spill.
    free_regs: Vec<Reg>,
}

// -------------------------------------------------------------------- entry

pub fn compile(program: &Program, arch: Arch) -> Result<Compiled, String> {
    compile_with_btf(program, arch, None)
}

pub fn compile_with_btf(program: &Program, arch: Arch, btf: Option<&Btf>) -> Result<Compiled, String> {
    let mut sh = Shared {
        events: Vec::new(),
        event_ids: HashMap::new(),
        maps: Vec::new(),
        map_index: HashMap::new(),
        map_types: HashMap::new(),
        consts: HashMap::new(),
        arch,
        btf,
        sample_map: None,
        usdt_map: None,
    };
    let mut probes = Vec::new();

    for item in &program.items {
        match item {
            Item::Event(e) => {
                let layout = layout_event(e)?;
                sh.event_ids.insert(e.name.name.clone(), sh.events.len() as u32);
                sh.events.push(layout);
            }
            Item::Const(c) => {
                sh.consts.insert(c.name.name.clone(), const_value(&c.value)?);
            }
            Item::Map(m) => {
                let (spec, kty, vty) = map_spec(m)?;
                sh.map_index.insert(m.name.name.clone(), (sh.maps.len() as i32) + 1);
                sh.map_types.insert(m.name.name.clone(), (kty, vty));
                sh.maps.push(spec);
            }
            Item::Probe(p) => probes.push(p),
        }
    }
    if probes.is_empty() {
        return Err("no probe to compile".into());
    }

    // Sampling: if any probe calls `sample()`, reserve a hidden array-map of
    // one u64 counter per call site.
    let sample_sites: u32 = probes.iter().map(|p| count_samples(&p.body)).sum();
    if sample_sites > 0 {
        let idx = (sh.maps.len() as i32) + 1;
        sh.sample_map = Some(idx);
        sh.maps.push(MapSpec {
            name: "__honey_sample".into(),
            kind: MapKind::Array,
            key_size: 4,
            value_size: 8,
            max_entries: sample_sites,
        });
    }

    // USDT: one argument spec per program (keyed by program index), filled
    // in by the loader from the marker's note.
    if probes.iter().any(|p| p.kind.name == "usdt") {
        let idx = (sh.maps.len() as i32) + 1;
        sh.usdt_map = Some(idx);
        sh.maps.push(MapSpec {
            name: "__honey_usdt".into(),
            kind: MapKind::Array,
            key_size: 4,
            value_size: USDT_SPEC_SIZE,
            max_entries: probes.len() as u32,
        });
    }

    let mut programs = Vec::new();
    let mut sample_next: u32 = 0;
    for (prog_index, p) in probes.into_iter().enumerate() {
        let kind = match (p.kind.name.as_str(), p.args.as_slice()) {
            ("tracepoint", [c, n]) => ProbeKind::Tracepoint { category: c.clone(), name: n.clone() },
            ("kprobe", [f]) => ProbeKind::Kprobe { function: f.clone() },
            ("kretprobe", [f]) => ProbeKind::Kretprobe { function: f.clone() },
            ("lsm", [h]) => ProbeKind::Lsm { hook: h.clone() },
            ("xdp", [i]) => ProbeKind::Xdp { interface: i.clone() },
            ("uprobe", [t]) => ProbeKind::Uprobe { target: t.clone() },
            ("uretprobe", [t]) => ProbeKind::Uretprobe { target: t.clone() },
            ("usdt", [t]) => ProbeKind::Usdt { target: t.clone() },
            (k, a) => return Err(format!("probe `{k}` with {} argument(s) is not supported", a.len())),
        };
        let name = match &kind {
            ProbeKind::Tracepoint { category, name } => format!("tracepoint:{category}:{name}"),
            ProbeKind::Kprobe { function } => format!("kprobe:{function}"),
            ProbeKind::Kretprobe { function } => format!("kretprobe:{function}"),
            ProbeKind::Lsm { hook } => format!("lsm:{hook}"),
            ProbeKind::Xdp { interface } => format!("xdp:{interface}"),
            ProbeKind::Uprobe { target } => format!("uprobe:{target}"),
            ProbeKind::Uretprobe { target } => format!("uretprobe:{target}"),
            ProbeKind::Usdt { target } => format!("usdt:{target}"),
        };
        let (bytecode, stack_bytes, relocs) = compile_probe(&sh, &kind, p, &mut sample_next, prog_index as u32)?;
        programs.push(CompiledProbe { name, kind, bytecode, stack_bytes, relocs });
    }

    let stack_bytes = programs.iter().map(|p| p.stack_bytes).max().unwrap_or(0);
    Ok(Compiled {
        programs,
        ringbuf_bytes: 1 << 16,
        maps: sh.maps,
        events: sh.events,
        license: "GPL".into(),
        arch,
        stack_bytes,
    })
}

fn compile_probe(sh: &Shared, kind: &ProbeKind, p: &ProbeDecl, sample_next: &mut u32, prog_index: u32) -> Result<(Vec<u8>, u32, Vec<Reloc>), String> {
    let mut prog = Prog::new();
    let exit_label = prog.new_label();
    let mut cg = Cg {
        sh,
        kind,
        prog,
        scopes: vec![HashMap::new()],
        local_consts: HashMap::new(),
        stack_top: 0,
        max_stack: 0,
        exit_label,
        ctx_slot: 0,
        relocs: Vec::new(),
        sample_next,
        prog_index,
        free_regs: free_callee_saved(kind, &p.body),
    };

    // Prologue: save the context pointer (R1) for `arg` / `retval`.
    cg.ctx_slot = cg.alloc_slot();
    cg.prog.push(stx_mem(Size::DW, Reg::R10, cg.ctx_slot, Reg::R1));

    if let ProbeKind::Xdp { .. } = kind {
        // R7 = packet start, R8 = packet end (callee-saved, survive helpers).
        // Loads from the xdp_md context are 32-bit; the verifier rewrites
        // them into full packet pointers.
        cg.prog.push(ldx_mem(Size::W, Reg::R7, Reg::R1, 0));
        cg.prog.push(ldx_mem(Size::W, Reg::R8, Reg::R1, 4));
        // One bounds check on entry covering the furthest read in the body:
        //   if data + MAX > data_end: pass (short packet)
        let bound = pkt_max_bound(&p.body, &sh.consts, sh.btf)?;
        if bound > 0 {
            cg.prog.push(mov64_reg(Reg::R2, Reg::R7));
            cg.prog.push(alu64_imm(AluOp::Add, Reg::R2, bound as i32));
            cg.prog.jmp_reg_to(JmpOp::Gt, Reg::R2, Reg::R8, cg.exit_label);
        }
    }

    cg.block(&p.body, true)?;

    // Epilogue: the probe's default return. XDP passes the packet; everything
    // else returns 0 (allow, for LSM).
    cg.prog.bind(cg.exit_label);
    let default_ret = if matches!(kind, ProbeKind::Xdp { .. }) { XDP_PASS } else { 0 };
    cg.prog.push(mov64_imm(Reg::R0, default_ret));
    cg.prog.push(bpf::exit());

    if cg.max_stack > BPF_STACK_LIMIT {
        return Err(format!(
            "probe uses {} bytes of stack, the BPF limit is {BPF_STACK_LIMIT}",
            cg.max_stack
        ));
    }
    let max_stack = cg.max_stack as u32;
    let reloc_sites = std::mem::take(&mut cg.relocs);
    let insns = cg.prog.resolve()?;
    // Map each reloc's instruction index to its byte-slot index (LD_IMM64
    // spans two slots, so index != slot).
    let mut slot_start = Vec::with_capacity(insns.len());
    let mut slot = 0usize;
    for insn in &insns {
        slot_start.push(slot);
        slot += insn.slots();
    }
    let relocs = reloc_sites
        .into_iter()
        .map(|(idx, st, f)| Reloc { slot: slot_start[idx], struct_name: st, field: f })
        .collect();
    let mut out = Vec::with_capacity(insns.len() * 8);
    for insn in &insns {
        insn.encode(&mut out);
    }
    Ok((out, max_stack, relocs))
}

fn const_value(e: &Expr) -> Result<i64, String> {
    match &e.kind {
        ExprKind::Int(n) => Ok(*n as i64),
        ExprKind::Bool(b) => Ok(*b as i64),
        _ => Err("const initialisers must be integer literals".into()),
    }
}

fn map_spec(m: &MapDecl) -> Result<(MapSpec, Ty, Ty), String> {
    let cap = u32::try_from(m.capacity).map_err(|_| "map capacity too large")?;
    match (m.kind.name.as_str(), m.args.as_slice()) {
        ("hash", [k, v]) => {
            let kty = Ty::from_ast(k)?;
            let vty = Ty::from_ast(v)?;
            let spec = MapSpec {
                name: m.name.name.clone(),
                kind: MapKind::Hash,
                key_size: kty.size(),
                value_size: vty.size(),
                max_entries: cap,
            };
            Ok((spec, kty, vty))
        }
        ("array", [v]) => {
            let vty = Ty::from_ast(v)?;
            let spec = MapSpec {
                name: m.name.name.clone(),
                kind: MapKind::Array,
                key_size: 4,
                value_size: vty.size(),
                max_entries: cap,
            };
            Ok((spec, Ty::Uint(4), vty))
        }
        (kind, args) => Err(format!(
            "map `{}`: unsupported kind `{kind}` with {} type argument(s)",
            m.name.name,
            args.len()
        )),
    }
}

/// Pre-pass over an XDP probe body: the largest `offset + width` of any
/// `pkt.u8/u16/u32(offset)` read, so one entry check can cover them all.
fn pkt_max_bound(body: &Block, consts: &HashMap<String, i64>, btf: Option<&Btf>) -> Result<u32, String> {
    fn eval(e: &Expr, consts: &HashMap<String, i64>) -> Result<i64, String> {
        match &e.kind {
            ExprKind::Int(n) => Ok(*n as i64),
            ExprKind::Ident(n) => consts.get(n).copied().ok_or_else(|| format!("packet offset `{n}` is not a constant")),
            ExprKind::Binary { op, lhs, rhs } => {
                let a = eval(lhs, consts)?;
                let b = eval(rhs, consts)?;
                Ok(match op {
                    BinaryOp::Add => a + b,
                    BinaryOp::Sub => a - b,
                    BinaryOp::Mul => a * b,
                    _ => return Err("unsupported operator in packet offset".into()),
                })
            }
            _ => Err("packet offset must be a constant".into()),
        }
    }
    fn expr(e: &Expr, consts: &HashMap<String, i64>, max: &mut u32) -> Result<(), String> {
        match &e.kind {
            ExprKind::MethodCall { receiver, method, args } => {
                if matches!(&receiver.kind, ExprKind::Ident(n) if n == "pkt") {
                    let width = match method.name.as_str() {
                        "u8" => 1,
                        "u16" => 2,
                        "u32" => 4,
                        "mac" => 6,
                        "ipv6" => 16,
                        _ => 0,
                    };
                    if width > 0
                        && let [off] = args.as_slice()
                    {
                        let o = eval(off, consts)?;
                        if o < 0 {
                            return Err("packet offset must not be negative".into());
                        }
                        *max = (*max).max(o as u32 + width);
                    }
                } else {
                    expr(receiver, consts, max)?;
                }
                for a in args {
                    expr(a, consts, max)?;
                }
                Ok(())
            }
            ExprKind::Unary { expr: inner, .. } | ExprKind::Cast { expr: inner, .. } => expr(inner, consts, max),
            ExprKind::Binary { lhs, rhs, .. } => {
                expr(lhs, consts, max)?;
                expr(rhs, consts, max)
            }
            ExprKind::Call { args, .. } => {
                for a in args {
                    expr(a, consts, max)?;
                }
                Ok(())
            }
            ExprKind::Field { expr: inner, .. } => expr(inner, consts, max),
            ExprKind::Index { expr: inner, index } => {
                expr(inner, consts, max)?;
                expr(index, consts, max)
            }
            _ => Ok(()),
        }
    }
    fn block(b: &Block, consts: &HashMap<String, i64>, max: &mut u32, btf: Option<&Btf>) -> Result<(), String> {
        for s in &b.stmts {
            match &s.kind {
                StmtKind::Let { value, ty: Some(t), .. } if t.name.name == "ptr" && is_pkt_at(value) => {
                    // a struct view covers offset .. offset + sizeof(struct)
                    let ExprKind::MethodCall { args, .. } = &value.kind else { unreachable!() };
                    let [off] = args.as_slice() else { return Err("`pkt.at` takes one constant offset".into()) };
                    let o = eval(off, consts)?;
                    let sname = match t.args.as_slice() {
                        [TypeArg::Type(inner)] => inner.name.name.clone(),
                        _ => return Err("`pkt.at` needs `ptr<Struct>`".into()),
                    };
                    let size = btf.and_then(|b| b.struct_size(&sname)).ok_or_else(|| format!("unknown struct `{sname}` (need --btf)"))?;
                    if o < 0 {
                        return Err("packet offset must not be negative".into());
                    }
                    *max = (*max).max(o as u32 + size);
                }
                StmtKind::Let { value, .. } => expr(value, consts, max)?,
                StmtKind::Assign { target, value } => {
                    expr(target, consts, max)?;
                    expr(value, consts, max)?;
                }
                StmtKind::If { cond, then, otherwise } => {
                    match cond {
                        Cond::Expr(e) => expr(e, consts, max)?,
                        Cond::Let { value, .. } => expr(value, consts, max)?,
                    }
                    block(then, consts, max, btf)?;
                    if let Some(o) = otherwise {
                        block(o, consts, max, btf)?;
                    }
                }
                StmtKind::For { start, end, body, .. } => {
                    expr(start, consts, max)?;
                    expr(end, consts, max)?;
                    block(body, consts, max, btf)?;
                }
                StmtKind::Emit { fields, .. } => {
                    for (_, v) in fields {
                        expr(v, consts, max)?;
                    }
                }
                StmtKind::Return(Some(e)) | StmtKind::Expr(e) => expr(e, consts, max)?,
                StmtKind::Return(None) => {}
            }
        }
        Ok(())
    }
    let mut max = 0;
    block(body, consts, &mut max, btf)?;
    Ok(max)
}

fn is_pkt_at(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::MethodCall { receiver, method, .. }
        if matches!(&receiver.kind, ExprKind::Ident(n) if n == "pkt") && method.name == "at")
}

/// Which of R6..R9 this probe may use for locals and temporaries.
fn free_callee_saved(kind: &ProbeKind, body: &Block) -> Vec<Reg> {
    let mut regs = vec![Reg::R9, Reg::R8, Reg::R7, Reg::R6];
    if body_has_emit(body) {
        regs.retain(|r| *r != Reg::R6);
    }
    if matches!(kind, ProbeKind::Xdp { .. }) {
        regs.retain(|r| !matches!(r, Reg::R7 | Reg::R8));
    }
    if matches!(kind, ProbeKind::Usdt { .. }) {
        regs.retain(|r| *r != Reg::R9);
    }
    regs
}

fn body_has_emit(body: &Block) -> bool {
    body.stmts.iter().any(|s| match &s.kind {
        StmtKind::Emit { .. } => true,
        StmtKind::If { then, otherwise, .. } => body_has_emit(then) || otherwise.as_ref().is_some_and(body_has_emit),
        StmtKind::For { body, .. } => body_has_emit(body),
        _ => false,
    })
}

/// Count `sample()` call sites in a probe body (for sizing the hidden map).
fn count_samples(body: &Block) -> u32 {
    fn expr(e: &Expr, n: &mut u32) {
        match &e.kind {
            ExprKind::Call { callee, args } => {
                if matches!(&callee.kind, ExprKind::Ident(name) if name == "sample") {
                    *n += 1;
                }
                for a in args {
                    expr(a, n);
                }
            }
            ExprKind::MethodCall { receiver, args, .. } => {
                expr(receiver, n);
                for a in args {
                    expr(a, n);
                }
            }
            ExprKind::Binary { lhs, rhs, .. } => {
                expr(lhs, n);
                expr(rhs, n);
            }
            ExprKind::Unary { expr: i, .. } | ExprKind::Cast { expr: i, .. } | ExprKind::Field { expr: i, .. } => expr(i, n),
            ExprKind::Index { expr: i, index } => {
                expr(i, n);
                expr(index, n);
            }
            _ => {}
        }
    }
    fn block(b: &Block, n: &mut u32) {
        for s in &b.stmts {
            match &s.kind {
                StmtKind::Let { value, .. } | StmtKind::Return(Some(value)) | StmtKind::Expr(value) => expr(value, n),
                StmtKind::Assign { target, value } => {
                    expr(target, n);
                    expr(value, n);
                }
                StmtKind::If { cond, then, otherwise } => {
                    match cond {
                        Cond::Expr(e) | Cond::Let { value: e, .. } => expr(e, n),
                    }
                    block(then, n);
                    if let Some(o) = otherwise {
                        block(o, n);
                    }
                }
                StmtKind::For { start, end, body, .. } => {
                    expr(start, n);
                    expr(end, n);
                    block(body, n);
                }
                StmtKind::Emit { fields, .. } => {
                    for (_, v) in fields {
                        expr(v, n);
                    }
                }
                StmtKind::Return(None) => {}
            }
        }
    }
    let mut n = 0;
    block(body, &mut n);
    n
}

fn str_capacity(t: &Type) -> Result<u32, String> {
    match t.args.as_slice() {
        [TypeArg::Int(n)] => u32::try_from(*n).map_err(|_| "str capacity too large".into()),
        _ => Err("`str` needs a capacity, e.g. `str<64>`".into()),
    }
}

/// Which jump implements a comparison, given whether operands are signed.
fn compare_op(op: BinaryOp, signed: bool) -> Option<JmpOp> {
    Some(match (op, signed) {
        (BinaryOp::Eq, _) => JmpOp::Eq,
        (BinaryOp::Ne, _) => JmpOp::Ne,
        (BinaryOp::Lt, false) => JmpOp::Lt,
        (BinaryOp::Le, false) => JmpOp::Le,
        (BinaryOp::Gt, false) => JmpOp::Gt,
        (BinaryOp::Ge, false) => JmpOp::Ge,
        (BinaryOp::Lt, true) => JmpOp::Slt,
        (BinaryOp::Le, true) => JmpOp::Sle,
        (BinaryOp::Gt, true) => JmpOp::Sgt,
        (BinaryOp::Ge, true) => JmpOp::Sge,
        _ => return None,
    })
}

fn is_comparison(op: BinaryOp) -> bool {
    matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge)
}

// --------------------------------------------------------------- statements

impl Cg<'_> {
    // ---- stack -----------------------------------------------------------

    fn alloc_slot(&mut self) -> i16 {
        self.stack_top += 8;
        self.max_stack = self.max_stack.max(self.stack_top);
        -(self.stack_top as i16)
    }

    fn free_slot(&mut self) {
        self.stack_top -= 8;
    }

    fn alloc_bytes(&mut self, n: u32) -> i16 {
        let rounded = n.div_ceil(8) * 8;
        self.stack_top += rounded as i32;
        self.max_stack = self.max_stack.max(self.stack_top);
        -(self.stack_top as i16)
    }

    /// Declare a scalar local: in a free callee-saved register if there is
    /// one, otherwise in a stack slot.
    fn declare(&mut self, name: &str, ty: Ty) -> Local {
        let local = match self.free_regs.pop() {
            Some(reg) => Local { off: 0, ty, reg: Some(reg) },
            None => Local { off: self.alloc_slot(), ty, reg: None },
        };
        self.scopes.last_mut().unwrap().insert(name.to_string(), local.clone());
        local
    }

    /// Store R0 into a local; load a local into R0.
    fn store_local(&mut self, local: &Local) {
        match local.reg {
            Some(r) => self.prog.push(mov64_reg(r, Reg::R0)),
            None => self.prog.push(stx_mem(Size::DW, Reg::R10, local.off, Reg::R0)),
        };
    }

    fn load_local(&mut self, local: &Local) {
        match local.reg {
            Some(r) => self.prog.push(mov64_reg(Reg::R0, r)),
            None => self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, local.off)),
        };
    }

    fn lookup(&self, name: &str) -> Option<&Local> {
        self.scopes.iter().rev().find_map(|s| s.get(name))
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    /// Pop a scope and release its stack. Strings occupy more than one slot,
    /// so release by size, not by count.
    fn pop_scope(&mut self) {
        let scope = self.scopes.pop().unwrap();
        for local in scope.values() {
            if let Some(r) = local.reg {
                self.free_regs.push(r);
                continue;
            }
            let bytes = match &local.ty {
                Ty::Str(n) => n.div_ceil(8) * 8,
                Ty::Ipv6 => 16,
                Ty::Mac => 8,
                Ty::PktPtr(..) => 0,
                _ => 8,
            };
            self.stack_top -= bytes as i32;
        }
    }

    fn const_lookup(&self, name: &str) -> Option<i64> {
        self.local_consts.get(name).or_else(|| self.sh.consts.get(name)).copied()
    }

    fn const_eval(&self, e: &Expr) -> Result<i64, String> {
        match &e.kind {
            ExprKind::Int(n) => Ok(*n as i64),
            ExprKind::Bool(b) => Ok(*b as i64),
            ExprKind::Ident(name) => self
                .const_lookup(name)
                .ok_or_else(|| format!("`{name}` is not a compile-time constant")),
            ExprKind::Binary { op, lhs, rhs } => {
                let a = self.const_eval(lhs)?;
                let b = self.const_eval(rhs)?;
                Ok(match op {
                    BinaryOp::Add => a + b,
                    BinaryOp::Sub => a - b,
                    BinaryOp::Mul => a * b,
                    BinaryOp::BitOr => a | b,
                    BinaryOp::BitAnd => a & b,
                    BinaryOp::Shl => a << b,
                    _ => return Err("unsupported operator in a constant expression".into()),
                })
            }
            _ => Err("expected a compile-time constant".into()),
        }
    }

    // ---- blocks ----------------------------------------------------------

    fn block(&mut self, b: &Block, top: bool) -> Result<(), String> {
        if !top {
            self.push_scope();
        }
        for s in &b.stmts {
            self.stmt(s)?;
        }
        if !top {
            self.pop_scope();
        }
        Ok(())
    }

    fn stmt(&mut self, s: &Stmt) -> Result<(), String> {
        match &s.kind {
            StmtKind::Let { name, ty, value, .. } => {
                if let Some(t) = ty
                    && t.name.name == "str"
                {
                    let n = str_capacity(t)?;
                    let off = self.alloc_bytes(n);
                    self.scopes.last_mut().unwrap().insert(name.name.clone(), Local { off, ty: Ty::Str(n), reg: None });
                    return self.read_str_into(off, n, value);
                }
                // Packet struct view: `let ip: ptr<iphdr> = pkt.at(14);` — a
                // compile-time binding, nothing emitted.
                if let Some(t) = ty
                    && t.name.name == "ptr"
                    && is_pkt_at(value)
                {
                    let sname = match t.args.as_slice() {
                        [TypeArg::Type(inner)] => inner.name.name.clone(),
                        _ => return Err("`pkt.at` needs `ptr<Struct>`".into()),
                    };
                    let ExprKind::MethodCall { args, .. } = &value.kind else { unreachable!() };
                    let [off] = args.as_slice() else { return Err("`pkt.at` takes one constant offset".into()) };
                    let o = i16::try_from(self.const_eval(off)?).map_err(|_| "packet offset too large")?;
                    self.scopes.last_mut().unwrap().insert(name.name.clone(), Local { off: 0, ty: Ty::PktPtr(sname, o), reg: None });
                    return Ok(());
                }
                // Byte blobs: `let a = pkt.ipv6(22);` copies straight from the packet.
                if let Some((width, off)) = self.pkt_blob(value)? {
                    let ty = if width == 16 { Ty::Ipv6 } else { Ty::Mac };
                    let dst = self.alloc_bytes(width);
                    self.scopes.last_mut().unwrap().insert(name.name.clone(), Local { off: dst, ty, reg: None });
                    self.copy_bytes(Reg::R7, off, Reg::R10, dst, width);
                    return Ok(());
                }
                let vty = self.expr(value)?;
                let ty = match ty {
                    Some(t) => Ty::from_ast(t)?,
                    None => vty,
                };
                let local = self.declare(&name.name, ty);
                self.store_local(&local);
                Ok(())
            }
            StmtKind::Assign { target, value } => {
                self.expr(value)?;
                match &target.kind {
                    ExprKind::Ident(n) => {
                        let local = self
                            .lookup(n)
                            .cloned()
                            .ok_or_else(|| format!("assignment to unknown variable `{n}`"))?;
                        self.store_local(&local);
                        Ok(())
                    }
                    _ => Err("unsupported assignment target".into()),
                }
            }
            StmtKind::If { cond, then, otherwise } => {
                let else_label = self.prog.new_label();
                let end_label = self.prog.new_label();
                let mut binding_scope = false;
                match cond {
                    Cond::Expr(e) => {
                        let then_label = self.prog.new_label();
                        self.cond(e, then_label, else_label)?;
                        self.prog.bind(then_label);
                    }
                    Cond::Let { pattern, value } => {
                        binding_scope = self.if_let_prelude(pattern, value, else_label)?;
                    }
                }
                self.block(then, false)?;
                if binding_scope {
                    self.pop_scope();
                }
                if otherwise.is_some() {
                    self.prog.ja_to(end_label);
                }
                self.prog.bind(else_label);
                if let Some(b) = otherwise {
                    self.block(b, false)?;
                }
                self.prog.bind(end_label);
                Ok(())
            }
            StmtKind::For { var, start, end, body } => {
                let lo = self.const_eval(start)?;
                let hi = self.const_eval(end)?;
                if hi < lo {
                    return Err("`for` end is before start".into());
                }
                if hi - lo > 64 {
                    return Err(format!("`for` unrolls {} iterations; the limit is 64", hi - lo));
                }
                for i in lo..hi {
                    let prev = self.local_consts.insert(var.name.clone(), i);
                    self.block(body, false)?;
                    match prev {
                        Some(v) => {
                            self.local_consts.insert(var.name.clone(), v);
                        }
                        None => {
                            self.local_consts.remove(&var.name);
                        }
                    }
                }
                Ok(())
            }
            StmtKind::Return(None) => {
                self.prog.ja_to(self.exit_label);
                Ok(())
            }
            StmtKind::Return(Some(_)) => Err("`return <value>` is not supported".into()),
            StmtKind::Emit { event, fields } => self.emit(event, fields),
            StmtKind::Expr(e) => {
                self.expr(e)?;
                Ok(())
            }
        }
    }

    /// `if let Some(x) = map.get(k)`: evaluate, spill, null-check. Returns
    /// whether a binding scope was pushed (the caller pops it).
    fn if_let_prelude(&mut self, pattern: &Pattern, value: &Expr, else_label: Label) -> Result<bool, String> {
        let ty = self.expr(value)?; // R0 = ptr or 0
        let Ty::OptionPtr(inner) = ty else {
            return Err("`if let` only works on the result of `map.get(...)`".into());
        };
        match (pattern.name.name.as_str(), &pattern.binding) {
            ("Some", Some(bind)) => {
                self.push_scope();
                let local = self.declare(&bind.name, Ty::ValuePtr(inner));
                // Park the pointer, then null-check R0. In a register the
                // verifier sees the check on a copy of the same value; on the
                // stack it propagates the check to the spilled slot.
                self.store_local(&local);
                self.prog.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, else_label);
                Ok(true)
            }
            ("None", None) => {
                self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, 0, else_label);
                Ok(false)
            }
            _ => Err("pattern must be `Some(name)` or `None`".into()),
        }
    }

    // ---- conditions ------------------------------------------------------

    fn cond(&mut self, e: &Expr, then_label: Label, else_label: Label) -> Result<(), String> {
        match &e.kind {
            ExprKind::Binary { op: BinaryOp::And, lhs, rhs } => {
                let mid = self.prog.new_label();
                self.cond(lhs, mid, else_label)?;
                self.prog.bind(mid);
                self.cond(rhs, then_label, else_label)
            }
            ExprKind::Binary { op: BinaryOp::Or, lhs, rhs } => {
                let mid = self.prog.new_label();
                self.cond(lhs, then_label, mid)?;
                self.prog.bind(mid);
                self.cond(rhs, then_label, else_label)
            }
            ExprKind::Unary { op: UnaryOp::Not, expr } => self.cond(expr, else_label, then_label),
            ExprKind::Binary { op, lhs, rhs } if is_comparison(*op) && !self.is_str_compare(lhs, rhs) => {
                if let Some((l, r)) = self.rewrite_ipv4_literal(lhs, rhs) {
                    let e2 = Expr { kind: ExprKind::Binary { op: *op, lhs: Box::new(l), rhs: Box::new(r) }, span: e.span };
                    return self.cond(&e2, then_label, else_label);
                }
                let (lty, rty) = self.binary_operands(lhs, rhs)?; // R1 = lhs, R0 = rhs
                let signed = lty == Ty::I64 || rty == Ty::I64;
                let jop = compare_op(*op, signed).unwrap();
                self.prog.jmp_reg_to(jop, Reg::R1, Reg::R0, then_label);
                self.prog.ja_to(else_label);
                Ok(())
            }
            _ => {
                self.expr(e)?;
                self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, 0, then_label);
                self.prog.ja_to(else_label);
                Ok(())
            }
        }
    }

    // ---- emit ------------------------------------------------------------

    fn emit(&mut self, event: &Ident, fields: &[(Ident, Expr)]) -> Result<(), String> {
        let id = *self
            .sh
            .event_ids
            .get(&event.name)
            .ok_or_else(|| format!("unknown event `{}`", event.name))?;
        let layout = self.sh.events[id as usize].clone();
        let total = RECORD_HEADER + layout.size;
        let skip = self.prog.new_label();

        // r0 = bpf_ringbuf_reserve(&ringbuf, total, 0); if !r0 skip
        self.prog.push(ld_map_fd(Reg::R1, RINGBUF_INDEX));
        self.prog.push(mov64_imm(Reg::R2, total as i32));
        self.prog.push(mov64_imm(Reg::R3, 0));
        self.prog.push(call(Helper::RingbufReserve));
        self.prog.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, skip);
        self.prog.push(mov64_reg(Reg::R6, Reg::R0));

        // Header: event id.
        self.prog.push(st_mem(Size::W, Reg::R6, 0, id as i32));
        self.prog.push(st_mem(Size::W, Reg::R6, 4, 0));

        for (fname, value) in fields {
            let fl = layout
                .fields
                .iter()
                .find(|f| f.name == fname.name)
                .ok_or_else(|| format!("event `{}` has no field `{}`", layout.name, fname.name))?;
            let off = i16::try_from(RECORD_HEADER + fl.offset).map_err(|_| "field offset too large")?;

            // comm() fills the field in place.
            if let ExprKind::Call { callee, args } = &value.kind
                && args.is_empty()
                && matches!(&callee.kind, ExprKind::Ident(n) if n == "comm")
            {
                let FieldKind::Str(n) = fl.kind else {
                    return Err("`comm()` must fill a `str<N>` field".into());
                };
                self.prog.push(mov64_reg(Reg::R1, Reg::R6));
                self.prog.push(alu64_imm(AluOp::Add, Reg::R1, off as i32));
                self.prog.push(mov64_imm(Reg::R2, n as i32));
                self.prog.push(call(Helper::GetCurrentComm));
                continue;
            }
            if let FieldKind::Str(cap) = fl.kind {
                let ExprKind::Ident(n) = &value.kind else {
                    return Err(format!("string field `{}` must be a `str` variable", fname.name));
                };
                let local = self.lookup(n).cloned().ok_or_else(|| format!("unknown variable `{n}`"))?;
                let Ty::Str(src_cap) = local.ty else {
                    return Err(format!("field `{}` expects a string", fname.name));
                };
                self.copy_str_to_record(local.off, off, src_cap.min(cap));
                continue;
            }
            if matches!(fl.kind, FieldKind::Ipv6 | FieldKind::Mac) {
                let width = fl.size;
                if let Some((w, poff)) = self.pkt_blob(value)? {
                    if w != width {
                        return Err(format!("field `{}` is {width} bytes but the packet read is {w}", fname.name));
                    }
                    self.copy_bytes(Reg::R7, poff, Reg::R6, off, width);
                    continue;
                }
                let ExprKind::Ident(n) = &value.kind else {
                    return Err(format!("field `{}` must be a `pkt.ipv6/mac(...)` read or a variable holding one", fname.name));
                };
                let local = self.lookup(n).cloned().ok_or_else(|| format!("unknown variable `{n}`"))?;
                if local.ty.size() != width {
                    return Err(format!("field `{}` is {width} bytes but `{n}` is {}", fname.name, local.ty.size()));
                }
                self.copy_bytes(Reg::R10, local.off, Reg::R6, off, width);
                continue;
            }
            let size = match fl.kind {
                FieldKind::Uint(w) | FieldKind::Sint(w) => Ty::Uint(w).mem_size(),
                FieldKind::Ipv4 => Size::W,
                FieldKind::Bool => Size::B,
                FieldKind::Str(_) | FieldKind::Ipv6 | FieldKind::Mac => unreachable!(),
            };
            self.expr(value)?;
            self.prog.push(stx_mem(size, Reg::R6, off, Reg::R0));
        }

        // bpf_ringbuf_submit(r6, 0)
        self.prog.push(mov64_reg(Reg::R1, Reg::R6));
        self.prog.push(mov64_imm(Reg::R2, 0));
        self.prog.push(call(Helper::RingbufSubmit));
        self.prog.bind(skip);
        Ok(())
    }

    // ---- expressions -----------------------------------------------------

    fn expr(&mut self, e: &Expr) -> Result<Ty, String> {
        match &e.kind {
            ExprKind::Int(n) => {
                self.load_imm(Reg::R0, *n as i64);
                Ok(Ty::Uint(8))
            }
            ExprKind::Bool(b) => {
                self.prog.push(mov64_imm(Reg::R0, *b as i32));
                Ok(Ty::Bool)
            }
            ExprKind::Str(_) => Err("string values are not supported in expressions".into()),
            ExprKind::Ident(name) => {
                if let Some(local) = self.lookup(name).cloned() {
                    if !matches!(local.ty, Ty::PktPtr(..)) {
                        self.load_local(&local);
                    }
                    return Ok(local.ty);
                }
                if let Some(v) = self.const_lookup(name) {
                    self.load_imm(Reg::R0, v);
                    return Ok(Ty::Uint(8));
                }
                Err(format!("unknown name `{name}`"))
            }
            ExprKind::Unary { op, expr } => match op {
                UnaryOp::Deref => match self.expr(expr)? {
                    Ty::ValuePtr(inner) => {
                        self.prog.push(ldx_mem(inner.mem_size(), Reg::R0, Reg::R0, 0));
                        Ok(*inner)
                    }
                    _ => Err("`*` applied to an unchecked or non-pointer value".into()),
                },
                UnaryOp::Neg => {
                    let ty = self.expr(expr)?;
                    self.prog.push(alu64_imm(AluOp::Neg, Reg::R0, 0));
                    Ok(ty)
                }
                UnaryOp::BitNot => {
                    let ty = self.expr(expr)?;
                    self.prog.push(alu64_imm(AluOp::Xor, Reg::R0, -1));
                    Ok(ty)
                }
                UnaryOp::Not => {
                    self.expr(expr)?;
                    let t = self.prog.new_label();
                    let end = self.prog.new_label();
                    self.prog.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, t);
                    self.prog.push(mov64_imm(Reg::R0, 0));
                    self.prog.ja_to(end);
                    self.prog.bind(t);
                    self.prog.push(mov64_imm(Reg::R0, 1));
                    self.prog.bind(end);
                    Ok(Ty::Bool)
                }
            },
            ExprKind::Binary { op, lhs, rhs } => self.binary(*op, lhs, rhs),
            ExprKind::Cast { .. } => Err("`as` casts are not supported".into()),
            ExprKind::Call { callee, args } => {
                let ExprKind::Ident(name) = &callee.kind else {
                    return Err("only builtins can be called".into());
                };
                if args.is_empty() {
                    self.builtin(name)
                } else {
                    self.builtin_with_args(name, args)
                }
            }
            ExprKind::MethodCall { receiver, method, args } => {
                if let ExprKind::Ident(n) = &receiver.kind
                    && n == "pkt"
                    && self.lookup("pkt").is_none()
                {
                    return self.pkt_method(&method.name, args);
                }
                if let ExprKind::Ident(n) = &receiver.kind {
                    if let Some(local) = self.lookup(n).cloned()
                        && let Ty::Str(cap) = local.ty
                    {
                        return self.str_method(local.off, cap, &method.name, args);
                    }
                    if self.sh.map_index.contains_key(n) {
                        return self.map_method(n, &method.name, args);
                    }
                }
                Err(format!("`.{}()` is only supported on maps and strings", method.name))
            }
            ExprKind::Field { expr, field } => {
                let base = self.expr(expr)?;
                if let Ty::PktPtr(sname, poff) = base {
                    return self.pkt_field(&sname, poff, &field.name);
                }
                let Ty::KPtr(sname) = base else {
                    return Err(format!("`.{}` needs a kernel struct pointer", field.name));
                };
                let btf = self.sh.btf.ok_or("kernel field access needs BTF")?;
                let member = btf
                    .member(&sname, &field.name)
                    .ok_or_else(|| format!("struct `{sname}` has no field `{}`", field.name))?;
                let off = member.offset_bytes as i32;
                match btf.resolve(member.type_id) {
                    Resolved::Struct { name } => {
                        // embedded struct: address = base + off (no read)
                        let idx = self.prog.len();
                        self.prog.push(alu64_imm(AluOp::Add, Reg::R0, off));
                        self.relocs.push((idx, sname.clone(), field.name.clone()));
                        Ok(Ty::KPtr(name))
                    }
                    Resolved::PtrToStruct { name } => {
                        self.emit_kernel_read(&sname, &field.name, off, 8);
                        Ok(Ty::KPtr(name))
                    }
                    Resolved::PtrToChar => {
                        self.emit_kernel_read(&sname, &field.name, off, 8);
                        Ok(Ty::KCharPtr)
                    }
                    Resolved::PtrToOther => {
                        self.emit_kernel_read(&sname, &field.name, off, 8);
                        Ok(Ty::Uint(8))
                    }
                    Resolved::Int { bytes, big_endian, .. } => {
                        self.emit_kernel_read(&sname, &field.name, off, bytes);
                        if big_endian && bytes >= 2 {
                            self.prog.push(bswap(Reg::R0, (bytes * 8) as u8));
                        }
                        Ok(Ty::Uint(bytes))
                    }
                    // A byte array (task_struct.comm): its address, for read_kernel_str.
                    Resolved::Array { elem_bytes: 1, .. } => {
                        let idx = self.prog.len();
                        self.prog.push(alu64_imm(AluOp::Add, Reg::R0, off));
                        self.relocs.push((idx, sname.clone(), field.name.clone()));
                        Ok(Ty::KCharPtr)
                    }
                    Resolved::Array { .. } | Resolved::Other => Err(format!("field `{}` has a type honey can't read", field.name)),
                }
            }
            ExprKind::Index { .. } => Err("indexing is not supported".into()),
        }
    }

    fn load_imm(&mut self, reg: Reg, v: i64) {
        if let Ok(small) = i32::try_from(v) {
            self.prog.push(mov64_imm(reg, small));
        } else {
            self.prog.push(ld_imm64(reg, v));
        }
    }

    /// Leaves lhs in R1 and rhs in R0. Returns both operand types. The lhs
    /// waits in a free callee-saved register while rhs is computed, or in a
    /// stack slot when none is free.
    fn binary_operands(&mut self, lhs: &Expr, rhs: &Expr) -> Result<(Ty, Ty), String> {
        let lty = self.expr(lhs)?;
        match self.free_regs.pop() {
            Some(t) => {
                self.prog.push(mov64_reg(t, Reg::R0));
                let rty = self.expr(rhs)?;
                self.prog.push(mov64_reg(Reg::R1, t));
                self.free_regs.push(t);
                Ok((lty, rty))
            }
            None => {
                let tmp = self.alloc_slot();
                self.prog.push(stx_mem(Size::DW, Reg::R10, tmp, Reg::R0));
                let rty = self.expr(rhs)?;
                self.prog.push(ldx_mem(Size::DW, Reg::R1, Reg::R10, tmp));
                self.free_slot();
                Ok((lty, rty))
            }
        }
    }

    /// Is this `a == b` / `a != b` a string comparison (a `str<N>` local on a
    /// side, or a literal)? The checker has already validated the shapes.
    fn is_str_compare(&self, lhs: &Expr, rhs: &Expr) -> bool {
        let is_str = |e: &Expr| match &e.kind {
            ExprKind::Str(_) => true,
            ExprKind::Ident(n) => matches!(self.lookup(n).map(|l| &l.ty), Some(Ty::Str(_) | Ty::Ipv6 | Ty::Mac)),
            _ => false,
        };
        is_str(lhs) || is_str(rhs)
    }

    /// `x == "10.0.0.1"` on a u32: the literal becomes the integer.
    fn rewrite_ipv4_literal(&self, lhs: &Expr, rhs: &Expr) -> Option<(Expr, Expr)> {
        let as_int = |e: &Expr| -> Option<Expr> {
            let ExprKind::Str(lit) = &e.kind else { return None };
            let v = addr::parse_ipv4(lit)?;
            Some(Expr { kind: ExprKind::Int(v as u64), span: e.span })
        };
        let blobby = |e: &Expr| matches!(&e.kind, ExprKind::Ident(n) if matches!(self.lookup(n).map(|l| &l.ty), Some(Ty::Str(_) | Ty::Ipv6 | Ty::Mac)));
        if blobby(lhs) || blobby(rhs) {
            return None;
        }
        if let Some(r) = as_int(rhs) {
            return Some((lhs.clone(), r));
        }
        if let Some(l) = as_int(lhs) {
            return Some((l, rhs.clone()));
        }
        None
    }

    /// `a == b` for ipv6/mac values: unrolled chunk compares. Result in R0.
    fn blob_equal(&mut self, lhs: &Expr, rhs: &Expr) -> Result<(), String> {
        enum Side {
            Local(i16, u32),
            Lit(Vec<u8>),
        }
        let side = |cg: &Self, e: &Expr, other_kind: Option<&Ty>| -> Result<Side, String> {
            match &e.kind {
                ExprKind::Ident(n) => match cg.lookup(n) {
                    Some(Local { off, ty: Ty::Ipv6, .. }) => Ok(Side::Local(*off, 16)),
                    Some(Local { off, ty: Ty::Mac, .. }) => Ok(Side::Local(*off, 6)),
                    _ => Err(format!("`{n}` is not an address")),
                },
                ExprKind::Str(lit) => match other_kind {
                    Some(Ty::Ipv6) => addr::parse_ipv6(lit).map(|b| Side::Lit(b.to_vec())).ok_or_else(|| format!("{lit:?} is not an ipv6 literal")),
                    Some(Ty::Mac) => addr::parse_mac(lit).map(|b| Side::Lit(b.to_vec())).ok_or_else(|| format!("{lit:?} is not a mac literal")),
                    _ => Err("address literal needs an address on the other side".into()),
                },
                _ => Err("address comparison needs a variable or a literal".into()),
            }
        };
        let kind_of = |cg: &Self, e: &Expr| -> Option<Ty> {
            if let ExprKind::Ident(n) = &e.kind { cg.lookup(n).map(|l| l.ty.clone()) } else { None }
        };
        let lk = kind_of(self, lhs);
        let rk = kind_of(self, rhs);
        let a = side(self, lhs, rk.as_ref())?;
        let b = side(self, rhs, lk.as_ref())?;
        let n = match (&a, &b) {
            (Side::Local(_, n), _) | (_, Side::Local(_, n)) => *n,
            _ => return Err("cannot compare two literals".into()),
        };
        let fail = self.prog.new_label();
        let end = self.prog.new_label();
        let mut done = 0u32;
        while done < n {
            let left = n - done;
            let (size, w) = if left >= 8 { (Size::DW, 8) } else if left >= 4 { (Size::W, 4) } else if left >= 2 { (Size::H, 2) } else { (Size::B, 1) };
            // chunk of A -> R1, chunk of B -> R0
            for (sd, reg) in [(&a, Reg::R1), (&b, Reg::R0)] {
                match sd {
                    Side::Local(off, _) => self.prog.push(ldx_mem(size, reg, Reg::R10, off + done as i16)),
                    Side::Lit(bytes) => {
                        // the bytes as the CPU would load them: little-endian
                        let mut buf = [0u8; 8];
                        buf[..w as usize].copy_from_slice(&bytes[done as usize..(done + w) as usize]);
                        self.prog.push(ld_imm64(reg, u64::from_le_bytes(buf) as i64))
                    }
                };
            }
            self.prog.jmp_reg_to(JmpOp::Ne, Reg::R1, Reg::R0, fail);
            done += w;
        }
        self.prog.push(mov64_imm(Reg::R0, 1));
        self.prog.ja_to(end);
        self.prog.bind(fail);
        self.prog.push(mov64_imm(Reg::R0, 0));
        self.prog.bind(end);
        Ok(())
    }

    /// Emit a string equality test into R0 (1 = equal). C-string semantics:
    /// equal through the terminating NUL, bounded by the capacities. Fully
    /// unrolled, so the verifier sees straight-line code.
    fn str_equal(&mut self, lhs: &Expr, rhs: &Expr) -> Result<(), String> {
        enum Side {
            Local(i16, u32),
            Lit(Vec<u8>),
        }
        let side = |cg: &Self, e: &Expr| -> Result<Side, String> {
            match &e.kind {
                ExprKind::Str(lit) => Ok(Side::Lit(lit.as_bytes().to_vec())),
                ExprKind::Ident(n) => match cg.lookup(n) {
                    Some(Local { off, ty: Ty::Str(cap), .. }) => Ok(Side::Local(*off, *cap)),
                    _ => Err(format!("`{n}` is not a string")),
                },
                _ => Err("string comparison needs a `str<N>` variable or a literal".into()),
            }
        };
        let (a, b) = (side(self, lhs)?, side(self, rhs)?);
        let fail = self.prog.new_label();
        let equal = self.prog.new_label();
        let end = self.prog.new_label();
        match (a, b) {
            (Side::Local(off, cap), Side::Lit(lit)) | (Side::Lit(lit), Side::Local(off, cap)) => {
                if lit.len() as u32 > cap {
                    return Err("literal longer than the string's capacity".into());
                }
                for (i, &byte) in lit.iter().enumerate() {
                    self.prog.push(ldx_mem(Size::B, Reg::R0, Reg::R10, off + i as i16));
                    self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, byte as i32, fail);
                }
                // The variable must end where the literal ends.
                if (lit.len() as u32) < cap {
                    self.prog.push(ldx_mem(Size::B, Reg::R0, Reg::R10, off + lit.len() as i16));
                    self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, 0, fail);
                }
            }
            (Side::Local(ao, ac), Side::Local(bo, bc)) => {
                let n = ac.min(bc);
                for i in 0..n as i16 {
                    self.prog.push(ldx_mem(Size::B, Reg::R1, Reg::R10, ao + i));
                    self.prog.push(ldx_mem(Size::B, Reg::R0, Reg::R10, bo + i));
                    self.prog.jmp_reg_to(JmpOp::Ne, Reg::R1, Reg::R0, fail);
                    // Same byte on both sides; if it's the NUL, both ended.
                    self.prog.jmp_imm_to(JmpOp::Eq, Reg::R1, 0, equal);
                }
                // Ran through the shorter capacity: the longer must end here.
                if ac > n {
                    self.prog.push(ldx_mem(Size::B, Reg::R0, Reg::R10, ao + n as i16));
                    self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, 0, fail);
                }
                if bc > n {
                    self.prog.push(ldx_mem(Size::B, Reg::R0, Reg::R10, bo + n as i16));
                    self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, 0, fail);
                }
            }
            (Side::Lit(_), Side::Lit(_)) => return Err("cannot compare two literals".into()),
        }
        self.prog.bind(equal);
        self.prog.push(mov64_imm(Reg::R0, 1));
        self.prog.ja_to(end);
        self.prog.bind(fail);
        self.prog.push(mov64_imm(Reg::R0, 0));
        self.prog.bind(end);
        Ok(())
    }

    fn binary(&mut self, op: BinaryOp, lhs: &Expr, rhs: &Expr) -> Result<Ty, String> {
        if matches!(op, BinaryOp::Eq | BinaryOp::Ne) {
            if let Some((l, r)) = self.rewrite_ipv4_literal(lhs, rhs) {
                return self.binary(op, &l, &r);
            }
            if self.is_str_compare(lhs, rhs) {
                let blob = |cg: &Self, e: &Expr| matches!(&e.kind, ExprKind::Ident(n) if matches!(cg.lookup(n).map(|l| &l.ty), Some(Ty::Ipv6 | Ty::Mac)));
                if blob(self, lhs) || blob(self, rhs) {
                    self.blob_equal(lhs, rhs)?;
                } else {
                    self.str_equal(lhs, rhs)?;
                }
                if op == BinaryOp::Ne {
                    self.prog.push(alu64_imm(AluOp::Xor, Reg::R0, 1));
                }
                return Ok(Ty::Bool);
            }
        }
        if matches!(op, BinaryOp::And | BinaryOp::Or) || is_comparison(op) {
            let t = self.prog.new_label();
            let f = self.prog.new_label();
            let end = self.prog.new_label();
            let e = Expr {
                kind: ExprKind::Binary { op, lhs: Box::new(lhs.clone()), rhs: Box::new(rhs.clone()) },
                span: lhs.span,
            };
            self.cond(&e, t, f)?;
            self.prog.bind(t);
            self.prog.push(mov64_imm(Reg::R0, 1));
            self.prog.ja_to(end);
            self.prog.bind(f);
            self.prog.push(mov64_imm(Reg::R0, 0));
            self.prog.bind(end);
            return Ok(Ty::Bool);
        }

        let (lty, rty) = self.binary_operands(lhs, rhs)?; // R1 = lhs, R0 = rhs
        let alu = match op {
            BinaryOp::Add => AluOp::Add,
            BinaryOp::Sub => AluOp::Sub,
            BinaryOp::Mul => AluOp::Mul,
            BinaryOp::Div => AluOp::Div,
            BinaryOp::Rem => AluOp::Mod,
            BinaryOp::BitAnd => AluOp::And,
            BinaryOp::BitOr => AluOp::Or,
            BinaryOp::BitXor => AluOp::Xor,
            BinaryOp::Shl => AluOp::Lsh,
            BinaryOp::Shr => AluOp::Rsh,
            _ => unreachable!(),
        };
        self.prog.push(alu64_reg(alu, Reg::R1, Reg::R0));
        self.prog.push(mov64_reg(Reg::R0, Reg::R1));
        // A literal operand (typed Uint(8) here) adopts the other side's type.
        Ok(if lty == Ty::I64 || rty == Ty::I64 { Ty::I64 } else { lty })
    }

    fn builtin(&mut self, name: &str) -> Result<Ty, String> {
        match name {
            "pid" | "tgid" => {
                self.prog.push(call(Helper::GetCurrentPidTgid));
                self.prog.push(alu64_imm(AluOp::Rsh, Reg::R0, 32));
                Ok(Ty::Uint(4))
            }
            "tid" => {
                self.prog.push(call(Helper::GetCurrentPidTgid));
                self.prog.push(alu32_reg(AluOp::Mov, Reg::R0, Reg::R0));
                Ok(Ty::Uint(4))
            }
            "uid" => {
                self.prog.push(call(Helper::GetCurrentUidGid));
                self.prog.push(alu32_reg(AluOp::Mov, Reg::R0, Reg::R0));
                Ok(Ty::Uint(4))
            }
            "gid" => {
                self.prog.push(call(Helper::GetCurrentUidGid));
                self.prog.push(alu64_imm(AluOp::Rsh, Reg::R0, 32));
                Ok(Ty::Uint(4))
            }
            "ktime" => {
                self.prog.push(call(Helper::KtimeGetNs));
                Ok(Ty::Uint(8))
            }
            "retval" => {
                if !matches!(self.kind, ProbeKind::Kretprobe { .. } | ProbeKind::Uretprobe { .. }) {
                    return Err("`retval()` is only available in a return probe".into());
                }
                let off = self.sh.arch.retval_offset();
                self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, self.ctx_slot));
                self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R0, off));
                Ok(Ty::I64)
            }
            "drop" => {
                self.prog.push(mov64_imm(Reg::R0, XDP_DROP));
                self.prog.push(bpf::exit());
                Ok(Ty::Uint(8))
            }
            "pass" => {
                self.prog.push(mov64_imm(Reg::R0, XDP_PASS));
                self.prog.push(bpf::exit());
                Ok(Ty::Uint(8))
            }
            "allow" => {
                // return 0 (allow) immediately.
                self.prog.push(mov64_imm(Reg::R0, 0));
                self.prog.push(bpf::exit());
                Ok(Ty::Uint(8))
            }
            "deny" => {
                // return -EPERM (-1) immediately: the LSM hook blocks the action.
                self.prog.push(mov64_imm(Reg::R0, -1));
                self.prog.push(bpf::exit());
                Ok(Ty::Uint(8))
            }
            "comm" => Err("`comm()` can only be used directly as an `emit` field value".into()),
            other => Err(format!("unknown builtin `{other}()`")),
        }
    }

    fn builtin_with_args(&mut self, name: &str, args: &[Expr]) -> Result<Ty, String> {
        match (name, args) {
            ("arg", [idx]) => {
                let n = self.const_eval(idx)?;
                let off = match self.kind {
                    ProbeKind::Tracepoint { .. } => {
                        if !(0..=5).contains(&n) {
                            return Err(format!("arg index {n} out of range"));
                        }
                        (16 + 8 * n) as i16
                    }
                    // LSM context is a u64 array of the hook's arguments.
                    ProbeKind::Lsm { .. } => {
                        if !(0..=5).contains(&n) {
                            return Err(format!("arg index {n} out of range"));
                        }
                        (8 * n) as i16
                    }
                    ProbeKind::Kprobe { .. } | ProbeKind::Uprobe { .. } => self
                        .sh
                        .arch
                        .kprobe_arg_offset(n)
                        .ok_or_else(|| format!("arg index {n} out of range for {}", self.sh.arch.name()))?,
                    ProbeKind::Kretprobe { .. } | ProbeKind::Uretprobe { .. } => {
                        return Err("`arg()` is not available in a return probe".into());
                    }
                    ProbeKind::Xdp { .. } => {
                        return Err("`arg()` is not available in an xdp probe".into());
                    }
                    ProbeKind::Usdt { .. } => {
                        if !(0..USDT_MAX_ARGS as i64).contains(&n) {
                            return Err(format!("usdt arg index {n} out of range (0..{})", USDT_MAX_ARGS - 1));
                        }
                        return self.emit_usdt_arg(n as u32);
                    }
                };
                self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, self.ctx_slot));
                self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R0, off));
                Ok(Ty::Uint(8))
            }
            ("sample", [n]) => {
                let rate = self.const_eval(n)?;
                self.emit_sample(rate)
            }
            ("in_subnet", [a, cidr]) => self.emit_in_subnet(a, cidr),
            ("read_user_str", _) => Err("`read_user_str` may only initialise a `str<N>` local".into()),
            (other, _) => Err(format!("builtin `{other}` does not take arguments here")),
        }
    }

    fn read_str_into(&mut self, off: i16, n: u32, value: &Expr) -> Result<(), String> {
        let ExprKind::Call { callee, args } = &value.kind else {
            return Err("a `str<N>` local must be initialised with `read_user_str`/`read_kernel_str`".into());
        };
        let helper = match &callee.kind {
            ExprKind::Ident(name) if name == "read_user_str" => Helper::ProbeReadUserStr,
            ExprKind::Ident(name) if name == "read_kernel_str" => Helper::ProbeReadKernelStr,
            _ => return Err("a `str<N>` local must be initialised with `read_user_str`/`read_kernel_str`".into()),
        };
        let [src] = args.as_slice() else {
            return Err("the string reader takes exactly one pointer argument".into());
        };
        self.expr(src)?; // R0 = source address
        self.prog.push(mov64_reg(Reg::R3, Reg::R0));
        self.prog.push(mov64_reg(Reg::R1, Reg::R10));
        self.prog.push(alu64_imm(AluOp::Add, Reg::R1, off as i32));
        self.prog.push(mov64_imm(Reg::R2, n as i32));
        self.prog.push(call(helper));
        Ok(())
    }

    /// Emit a BTF-relocated read of `size` bytes from `[R0 + field_offset]`
    /// into R0. Records the offset instruction as a relocation site.
    fn emit_kernel_read(&mut self, struct_name: &str, field: &str, off: i32, size: u32) {
        self.prog.push(mov64_reg(Reg::R3, Reg::R0)); // R3 = base address
        let idx = self.prog.len();
        self.prog.push(alu64_imm(AluOp::Add, Reg::R3, off)); // <- reloc site
        self.relocs.push((idx, struct_name.to_string(), field.to_string()));
        let tmp = self.alloc_slot();
        self.prog.push(mov64_reg(Reg::R1, Reg::R10));
        self.prog.push(alu64_imm(AluOp::Add, Reg::R1, tmp as i32));
        self.prog.push(mov64_imm(Reg::R2, size as i32));
        self.prog.push(call(Helper::ProbeReadKernel));
        let szenum = match size {
            1 => Size::B,
            2 => Size::H,
            4 => Size::W,
            _ => Size::DW,
        };
        self.prog.push(ldx_mem(szenum, Reg::R0, Reg::R10, tmp));
        self.free_slot();
    }

    /// `pkt.u8/u16/u32(off)` and `pkt.len()`. R7 = data, R8 = data_end, and
    /// the prologue proved `data + bound <= data_end` for every offset used,
    /// so these loads are plain and the verifier accepts them.
    fn pkt_method(&mut self, method: &str, args: &[Expr]) -> Result<Ty, String> {
        if !matches!(self.kind, ProbeKind::Xdp { .. }) {
            return Err("`pkt` is only available in an xdp probe".into());
        }
        match (method, args) {
            ("len", []) => {
                self.prog.push(mov64_reg(Reg::R0, Reg::R8));
                self.prog.push(alu64_reg(AluOp::Sub, Reg::R0, Reg::R7));
                Ok(Ty::Uint(4))
            }
            ("u8", [off]) => {
                let o = i16::try_from(self.const_eval(off)?).map_err(|_| "packet offset too large")?;
                self.prog.push(ldx_mem(Size::B, Reg::R0, Reg::R7, o));
                Ok(Ty::Uint(1))
            }
            ("u16", [off]) => {
                let o = i16::try_from(self.const_eval(off)?).map_err(|_| "packet offset too large")?;
                self.prog.push(ldx_mem(Size::H, Reg::R0, Reg::R7, o));
                self.prog.push(bswap(Reg::R0, 16)); // network -> host order
                Ok(Ty::Uint(2))
            }
            ("u32", [off]) => {
                let o = i16::try_from(self.const_eval(off)?).map_err(|_| "packet offset too large")?;
                self.prog.push(ldx_mem(Size::W, Reg::R0, Reg::R7, o));
                self.prog.push(bswap(Reg::R0, 32));
                Ok(Ty::Uint(4))
            }
            ("ipv6" | "mac", _) => Err(format!("`pkt.{method}` is a byte blob: bind it with `let` or emit it directly")),
            (m, a) => Err(format!("`pkt` has no method `{m}` taking {} argument(s)", a.len())),
        }
    }

    /// `arg(n)` in a usdt probe: a generic read driven by the per-probe spec
    /// the loader filled in (see `USDT_SPEC_SIZE`). At runtime: fetch the
    /// spec, and depending on the arg's kind read a register out of pt_regs
    /// (via probe_read_kernel on ctx + reg_off), optionally dereference it
    /// in user memory, then shift to extract the sized value with the right
    /// signedness. Mirrors libbpf's usdt.bpf.h. Result in R0 as a u64.
    fn emit_usdt_arg(&mut self, n: u32) -> Result<Ty, String> {
        let map_idx = self.sh.usdt_map.ok_or("internal: usdt spec map not reserved")?;
        let base = (USDT_ARG_SIZE * n) as i16;
        let zero = self.prog.new_label();
        let done = self.prog.new_label();
        let notconst = self.prog.new_label();
        let shift = self.prog.new_label();
        let unsigned = self.prog.new_label();

        // r0 = spec = lookup(usdt_map, &prog_index)
        let kslot = self.alloc_slot();
        self.prog.push(st_mem(Size::W, Reg::R10, kslot, self.prog_index as i32));
        self.prog.push(ld_map_fd(Reg::R1, map_idx));
        self.prog.push(mov64_reg(Reg::R2, Reg::R10));
        self.prog.push(alu64_imm(AluOp::Add, Reg::R2, kslot as i32));
        self.prog.push(call(Helper::MapLookupElem));
        self.free_slot();
        self.prog.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, zero);
        // r9 = spec (callee-saved: survives the helper calls below)
        self.prog.push(mov64_reg(Reg::R9, Reg::R0));

        // kind
        self.prog.push(ldx_mem(Size::B, Reg::R1, Reg::R9, base));
        self.prog.jmp_imm_to(JmpOp::Eq, Reg::R1, USDT_KIND_NONE, zero);
        self.prog.jmp_imm_to(JmpOp::Ne, Reg::R1, USDT_KIND_CONST, notconst);
        self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R9, base + 8)); // constant value
        self.prog.ja_to(done);

        // register: probe_read_kernel(&tmp, 8, ctx + reg_off)
        self.prog.bind(notconst);
        let tmp = self.alloc_slot();
        self.prog.push(ldx_mem(Size::H, Reg::R2, Reg::R9, base + 4));
        self.prog.push(ldx_mem(Size::DW, Reg::R3, Reg::R10, self.ctx_slot));
        self.prog.push(alu64_reg(AluOp::Add, Reg::R3, Reg::R2));
        self.prog.push(mov64_reg(Reg::R1, Reg::R10));
        self.prog.push(alu64_imm(AluOp::Add, Reg::R1, tmp as i32));
        self.prog.push(mov64_imm(Reg::R2, 8));
        self.prog.push(call(Helper::ProbeReadKernel));
        self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, tmp));

        // memory: probe_read_user(&tmp, 8, reg + val)
        self.prog.push(ldx_mem(Size::B, Reg::R1, Reg::R9, base));
        self.prog.jmp_imm_to(JmpOp::Ne, Reg::R1, USDT_KIND_MEM, shift);
        self.prog.push(ldx_mem(Size::DW, Reg::R3, Reg::R9, base + 8));
        self.prog.push(alu64_reg(AluOp::Add, Reg::R3, Reg::R0));
        self.prog.push(mov64_reg(Reg::R1, Reg::R10));
        self.prog.push(alu64_imm(AluOp::Add, Reg::R1, tmp as i32));
        self.prog.push(mov64_imm(Reg::R2, 8));
        self.prog.push(call(Helper::ProbeReadUser));
        self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, tmp));

        // extract the sized value: val <<= shift; signed ? arsh : rsh
        self.prog.bind(shift);
        self.free_slot();
        self.prog.push(ldx_mem(Size::B, Reg::R4, Reg::R9, base + 2));
        self.prog.push(alu64_reg(AluOp::Lsh, Reg::R0, Reg::R4));
        self.prog.push(ldx_mem(Size::B, Reg::R1, Reg::R9, base + 1));
        self.prog.jmp_imm_to(JmpOp::Eq, Reg::R1, 0, unsigned);
        self.prog.push(alu64_reg(AluOp::Arsh, Reg::R0, Reg::R4));
        self.prog.ja_to(done);
        self.prog.bind(unsigned);
        self.prog.push(alu64_reg(AluOp::Rsh, Reg::R0, Reg::R4));
        self.prog.ja_to(done);

        self.prog.bind(zero);
        self.prog.push(mov64_imm(Reg::R0, 0));
        self.prog.bind(done);
        Ok(Ty::Uint(8))
    }

    /// `sample(N)`: true on 1 of every N calls. Backed by a per-site counter
    /// in the hidden `__honey_sample` array map. Result (0/1) lands in R0.
    fn emit_sample(&mut self, rate: i64) -> Result<Ty, String> {
        let map_idx = self.sh.sample_map.ok_or("internal: sample map not reserved")?;
        let site = *self.sample_next as i32;
        *self.sample_next += 1;

        let miss = self.prog.new_label();
        let end = self.prog.new_label();

        // key = site index -> stack; r0 = array_lookup(map, &key)
        let kslot = self.alloc_slot();
        self.prog.push(st_mem(Size::W, Reg::R10, kslot, site));
        self.prog.push(ld_map_fd(Reg::R1, map_idx));
        self.prog.push(mov64_reg(Reg::R2, Reg::R10));
        self.prog.push(alu64_imm(AluOp::Add, Reg::R2, kslot as i32));
        self.prog.push(call(Helper::MapLookupElem));
        self.free_slot();
        // array lookups shouldn't fail, but the verifier needs the null check.
        self.prog.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, miss);
        // c = *r0 + 1; *r0 = c   (map_value pointer is writable)
        self.prog.push(ldx_mem(Size::DW, Reg::R1, Reg::R0, 0));
        self.prog.push(alu64_imm(AluOp::Add, Reg::R1, 1));
        self.prog.push(stx_mem(Size::DW, Reg::R0, 0, Reg::R1));
        // result = (c % rate == 0)
        self.prog.push(alu64_imm(AluOp::Mod, Reg::R1, rate as i32));
        self.prog.push(mov64_imm(Reg::R0, 0));
        self.prog.jmp_imm_to(JmpOp::Ne, Reg::R1, 0, end);
        self.prog.push(mov64_imm(Reg::R0, 1));
        self.prog.ja_to(end);
        self.prog.bind(miss);
        self.prog.push(mov64_imm(Reg::R0, 0));
        self.prog.bind(end);
        Ok(Ty::Bool)
    }

    /// Read `view.field` from the packet at a constant offset. Scalars are
    /// plain loads (byte-swapped when the kernel declares the field `__be*`);
    /// embedded structs are views at a deeper offset; 6/16-byte arrays and
    /// `in6_addr` are blobs (handled by `pkt_blob` at let/emit sites).
    fn pkt_field(&mut self, sname: &str, poff: i16, field: &str) -> Result<Ty, String> {
        let btf = self.sh.btf.ok_or("packet struct access needs BTF")?;
        let member = btf.member(sname, field).ok_or_else(|| format!("struct `{sname}` has no field `{field}`"))?;
        if member.bitfield {
            return Err(format!("`{field}` is a bitfield"));
        }
        let off = poff + member.offset_bytes as i16;
        match btf.resolve(member.type_id) {
            Resolved::Int { bytes, big_endian, .. } => {
                let size = match bytes {
                    1 => Size::B,
                    2 => Size::H,
                    4 => Size::W,
                    _ => Size::DW,
                };
                self.prog.push(ldx_mem(size, Reg::R0, Reg::R7, off));
                if big_endian && bytes >= 2 {
                    self.prog.push(bswap(Reg::R0, (bytes * 8) as u8));
                }
                Ok(Ty::Uint(bytes))
            }
            Resolved::Struct { name } if name == "in6_addr" => Err("`in6_addr` is a 16-byte value: bind it with `let` or emit it".into()),
            Resolved::Struct { name } => Ok(Ty::PktPtr(name, off)),
            Resolved::Array { elem_bytes: 1, len: 6 | 16 } => Err(format!("`{field}` is a byte blob: bind it with `let` or emit it directly")),
            _ => Err(format!("field `{field}` has a type honey can't read from a packet")),
        }
    }

    /// `in_subnet(addr, "cidr")` → R0 = 1 if the address is in the network.
    fn emit_in_subnet(&mut self, a: &Expr, cidr: &Expr) -> Result<Ty, String> {
        let ExprKind::Str(lit) = &cidr.kind else { return Err("`in_subnet` takes a CIDR literal".into()) };
        // ipv6 local?
        if let ExprKind::Ident(n) = &a.kind
            && let Some(Local { off, ty: Ty::Ipv6, .. }) = self.lookup(n).cloned()
        {
            let (net, len) = addr::parse_cidr6(lit).ok_or_else(|| format!("{lit:?} is not an IPv6 CIDR"))?;
            let mask = addr::mask6(len);
            let fail = self.prog.new_label();
            let end = self.prog.new_label();
            for chunk in 0..2i16 {
                let i = (chunk * 8) as usize;
                let m = u64::from_le_bytes(mask[i..i + 8].try_into().unwrap());
                if m == 0 {
                    continue;
                }
                let mut nb = [0u8; 8];
                for k in 0..8 {
                    nb[k] = net[i + k] & mask[i + k];
                }
                let want = u64::from_le_bytes(nb);
                self.prog.push(ldx_mem(Size::DW, Reg::R1, Reg::R10, off + chunk * 8));
                self.prog.push(ld_imm64(Reg::R0, m as i64));
                self.prog.push(alu64_reg(AluOp::And, Reg::R1, Reg::R0));
                self.prog.push(ld_imm64(Reg::R0, want as i64));
                self.prog.jmp_reg_to(JmpOp::Ne, Reg::R1, Reg::R0, fail);
            }
            self.prog.push(mov64_imm(Reg::R0, 1));
            self.prog.ja_to(end);
            self.prog.bind(fail);
            self.prog.push(mov64_imm(Reg::R0, 0));
            self.prog.bind(end);
            return Ok(Ty::Bool);
        }
        // u32 address: (addr & mask) == (net & mask)
        let (net, len) = addr::parse_cidr4(lit).ok_or_else(|| format!("{lit:?} is not an IPv4 CIDR"))?;
        let mask = addr::mask4(len);
        self.expr(a)?; // R0 = addr (host order)
        self.load_imm(Reg::R1, mask as i64);
        self.prog.push(alu64_reg(AluOp::And, Reg::R0, Reg::R1));
        self.load_imm(Reg::R1, (net & mask) as i64);
        let t = self.prog.new_label();
        let end = self.prog.new_label();
        self.prog.jmp_reg_to(JmpOp::Eq, Reg::R0, Reg::R1, t);
        self.prog.push(mov64_imm(Reg::R0, 0));
        self.prog.ja_to(end);
        self.prog.bind(t);
        self.prog.push(mov64_imm(Reg::R0, 1));
        self.prog.bind(end);
        Ok(Ty::Bool)
    }

    /// If `e` is `pkt.ipv6(off)` / `pkt.mac(off)` — or a blob-typed field of a
    /// packet view — return (width, packet offset).
    fn pkt_blob(&self, e: &Expr) -> Result<Option<(u32, i16)>, String> {
        if let ExprKind::Field { expr, field } = &e.kind
            && let ExprKind::Ident(n) = &expr.kind
            && let Some(Local { ty: Ty::PktPtr(sname, poff), .. }) = self.lookup(n).cloned()
        {
            let btf = self.sh.btf.ok_or("packet struct access needs BTF")?;
            let member = btf.member(&sname, &field.name).ok_or_else(|| format!("struct `{sname}` has no field `{}`", field.name))?;
            let off = poff + member.offset_bytes as i16;
            return Ok(match btf.resolve(member.type_id) {
                Resolved::Array { elem_bytes: 1, len: 6 } => Some((6, off)),
                Resolved::Array { elem_bytes: 1, len: 16 } => Some((16, off)),
                Resolved::Struct { name } if name == "in6_addr" => Some((16, off)),
                _ => None,
            });
        }
        let ExprKind::MethodCall { receiver, method, args } = &e.kind else { return Ok(None) };
        if !matches!(&receiver.kind, ExprKind::Ident(n) if n == "pkt" && self.lookup("pkt").is_none()) {
            return Ok(None);
        }
        let width = match method.name.as_str() {
            "ipv6" => 16,
            "mac" => 6,
            _ => return Ok(None),
        };
        if !matches!(self.kind, ProbeKind::Xdp { .. }) {
            return Err("`pkt` is only available in an xdp probe".into());
        }
        let [off] = args.as_slice() else {
            return Err(format!("`pkt.{}` takes one constant offset", method.name));
        };
        let o = i16::try_from(self.const_eval(off)?).map_err(|_| "packet offset too large")?;
        Ok(Some((width, o)))
    }

    /// Copy `n` bytes from `[src + soff]` to `[dst + doff]` in 8/4/2/1-byte
    /// chunks through R0. Sources may be the packet (R7) or the stack (R10);
    /// destinations the stack or the ring-buffer record (R6).
    fn copy_bytes(&mut self, src: Reg, soff: i16, dst: Reg, doff: i16, n: u32) {
        let mut done: u32 = 0;
        while done < n {
            let left = n - done;
            let (size, w) = if left >= 8 {
                (Size::DW, 8)
            } else if left >= 4 {
                (Size::W, 4)
            } else if left >= 2 {
                (Size::H, 2)
            } else {
                (Size::B, 1)
            };
            self.prog.push(ldx_mem(size, Reg::R0, src, soff + done as i16));
            self.prog.push(stx_mem(size, dst, doff + done as i16, Reg::R0));
            done += w;
        }
    }

    fn str_method(&mut self, off: i16, cap: u32, method: &str, args: &[Expr]) -> Result<Ty, String> {
        match (method, args) {
            ("starts_with", [arg]) => {
                let ExprKind::Str(lit) = &arg.kind else {
                    return Err("`starts_with` takes a string literal".into());
                };
                let bytes = lit.as_bytes();
                if bytes.len() as u32 > cap {
                    return Err(format!("prefix {lit:?} is longer than the str<{cap}> it tests"));
                }
                let fail = self.prog.new_label();
                let end = self.prog.new_label();
                for (i, &b) in bytes.iter().enumerate() {
                    self.prog.push(ldx_mem(Size::B, Reg::R0, Reg::R10, off + i as i16));
                    self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, b as i32, fail);
                }
                self.prog.push(mov64_imm(Reg::R0, 1));
                self.prog.ja_to(end);
                self.prog.bind(fail);
                self.prog.push(mov64_imm(Reg::R0, 0));
                self.prog.bind(end);
                Ok(Ty::Bool)
            }
            ("byte_at", [arg]) => {
                let i = self.const_eval(arg)?;
                if i < 0 || i as u32 >= cap {
                    return Err(format!("byte_at({i}) is outside str<{cap}>"));
                }
                self.prog.push(ldx_mem(Size::B, Reg::R0, Reg::R10, off + i as i16));
                Ok(Ty::Uint(1))
            }
            (m, a) => Err(format!("string has no method `{m}` taking {} argument(s)", a.len())),
        }
    }

    fn copy_str_to_record(&mut self, src: i16, dst: i16, n: u32) {
        let words = n.div_ceil(8);
        for w in 0..words as i16 {
            self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, src + w * 8));
            self.prog.push(stx_mem(Size::DW, Reg::R6, dst + w * 8, Reg::R0));
        }
    }

    fn map_method(&mut self, map: &str, method: &str, args: &[Expr]) -> Result<Ty, String> {
        let idx = self.sh.map_index[map];
        let (kty, vty) = self.sh.map_types[map].clone();
        match (method, args) {
            ("get", [key]) => {
                self.expr(key)?;
                let kslot = self.alloc_slot();
                self.prog.push(stx_mem(kty.mem_size(), Reg::R10, kslot, Reg::R0));
                self.prog.push(ld_map_fd(Reg::R1, idx));
                self.prog.push(mov64_reg(Reg::R2, Reg::R10));
                self.prog.push(alu64_imm(AluOp::Add, Reg::R2, kslot as i32));
                self.prog.push(call(Helper::MapLookupElem));
                self.free_slot();
                Ok(Ty::OptionPtr(Box::new(vty)))
            }
            ("insert", [key, value]) => {
                self.expr(key)?;
                let kslot = self.alloc_slot();
                self.prog.push(stx_mem(kty.mem_size(), Reg::R10, kslot, Reg::R0));
                self.expr(value)?;
                let vslot = self.alloc_slot();
                self.prog.push(stx_mem(vty.mem_size(), Reg::R10, vslot, Reg::R0));
                self.prog.push(ld_map_fd(Reg::R1, idx));
                self.prog.push(mov64_reg(Reg::R2, Reg::R10));
                self.prog.push(alu64_imm(AluOp::Add, Reg::R2, kslot as i32));
                self.prog.push(mov64_reg(Reg::R3, Reg::R10));
                self.prog.push(alu64_imm(AluOp::Add, Reg::R3, vslot as i32));
                self.prog.push(mov64_imm(Reg::R4, 0)); // BPF_ANY
                self.prog.push(call(Helper::MapUpdateElem));
                self.free_slot();
                self.free_slot();
                Ok(Ty::Uint(8))
            }
            ("delete", [key]) => {
                self.expr(key)?;
                let kslot = self.alloc_slot();
                self.prog.push(stx_mem(kty.mem_size(), Reg::R10, kslot, Reg::R0));
                self.prog.push(ld_map_fd(Reg::R1, idx));
                self.prog.push(mov64_reg(Reg::R2, Reg::R10));
                self.prog.push(alu64_imm(AluOp::Add, Reg::R2, kslot as i32));
                self.prog.push(call(Helper::MapDeleteElem));
                self.free_slot();
                Ok(Ty::Uint(8))
            }
            (m, a) => Err(format!("map `{map}` has no method `{m}` taking {} argument(s)", a.len())),
        }
    }
}
