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
}

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

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
    ValuePtr(Box<Ty>),
    OptionPtr(Box<Ty>),
    /// Kernel pointer to a named struct (an address).
    KPtr(String),
    /// Kernel pointer to char (a string address).
    KCharPtr,
}

impl Ty {
    fn from_ast(t: &Type) -> Result<Ty, String> {
        match (t.name.name.as_str(), t.args.as_slice()) {
            ("u8", []) => Ok(Ty::Uint(1)),
            ("u16", []) => Ok(Ty::Uint(2)),
            ("u32", []) => Ok(Ty::Uint(4)),
            ("u64", []) => Ok(Ty::Uint(8)),
            ("i64", []) => Ok(Ty::I64),
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
            Ty::I64 | Ty::ValuePtr(_) | Ty::OptionPtr(_) | Ty::KPtr(_) | Ty::KCharPtr => 8,
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
    off: i16,
    ty: Ty,
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

    let mut programs = Vec::new();
    let mut sample_next: u32 = 0;
    for p in probes {
        let kind = match (p.kind.name.as_str(), p.args.as_slice()) {
            ("tracepoint", [c, n]) => ProbeKind::Tracepoint { category: c.clone(), name: n.clone() },
            ("kprobe", [f]) => ProbeKind::Kprobe { function: f.clone() },
            ("kretprobe", [f]) => ProbeKind::Kretprobe { function: f.clone() },
            ("lsm", [h]) => ProbeKind::Lsm { hook: h.clone() },
            ("xdp", [i]) => ProbeKind::Xdp { interface: i.clone() },
            ("uprobe", [t]) => ProbeKind::Uprobe { target: t.clone() },
            ("uretprobe", [t]) => ProbeKind::Uretprobe { target: t.clone() },
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
        };
        let (bytecode, stack_bytes, relocs) = compile_probe(&sh, &kind, p, &mut sample_next)?;
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

fn compile_probe(sh: &Shared, kind: &ProbeKind, p: &ProbeDecl, sample_next: &mut u32) -> Result<(Vec<u8>, u32, Vec<Reloc>), String> {
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
        let bound = pkt_max_bound(&p.body, &sh.consts)?;
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
fn pkt_max_bound(body: &Block, consts: &HashMap<String, i64>) -> Result<u32, String> {
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
    fn block(b: &Block, consts: &HashMap<String, i64>, max: &mut u32) -> Result<(), String> {
        for s in &b.stmts {
            match &s.kind {
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
                    block(then, consts, max)?;
                    if let Some(o) = otherwise {
                        block(o, consts, max)?;
                    }
                }
                StmtKind::For { start, end, body, .. } => {
                    expr(start, consts, max)?;
                    expr(end, consts, max)?;
                    block(body, consts, max)?;
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
    block(body, consts, &mut max)?;
    Ok(max)
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

    fn declare(&mut self, name: &str, ty: Ty) -> Local {
        let off = self.alloc_slot();
        let local = Local { off, ty };
        self.scopes.last_mut().unwrap().insert(name.to_string(), local.clone());
        local
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
            let bytes = match &local.ty {
                Ty::Str(n) => n.div_ceil(8) * 8,
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
                    self.scopes.last_mut().unwrap().insert(name.name.clone(), Local { off, ty: Ty::Str(n) });
                    return self.read_str_into(off, n, value);
                }
                let vty = self.expr(value)?;
                let ty = match ty {
                    Some(t) => Ty::from_ast(t)?,
                    None => vty,
                };
                let local = self.declare(&name.name, ty);
                self.prog.push(stx_mem(Size::DW, Reg::R10, local.off, Reg::R0));
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
                        self.prog.push(stx_mem(Size::DW, Reg::R10, local.off, Reg::R0));
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
                self.prog.push(stx_mem(Size::DW, Reg::R10, local.off, Reg::R0));
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
            ExprKind::Binary { op, lhs, rhs } if is_comparison(*op) => {
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
            let size = match fl.kind {
                FieldKind::Uint(w) | FieldKind::Sint(w) => Ty::Uint(w).mem_size(),
                FieldKind::Bool => Size::B,
                FieldKind::Str(_) => unreachable!(),
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
                    self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, local.off));
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
                    Resolved::Int { bytes, .. } => {
                        self.emit_kernel_read(&sname, &field.name, off, bytes);
                        Ok(Ty::Uint(bytes))
                    }
                    Resolved::Other => Err(format!("field `{}` has a type honey can't read", field.name)),
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

    /// Leaves lhs in R1 and rhs in R0. Returns both operand types.
    fn binary_operands(&mut self, lhs: &Expr, rhs: &Expr) -> Result<(Ty, Ty), String> {
        let lty = self.expr(lhs)?;
        let tmp = self.alloc_slot();
        self.prog.push(stx_mem(Size::DW, Reg::R10, tmp, Reg::R0));
        let rty = self.expr(rhs)?;
        self.prog.push(ldx_mem(Size::DW, Reg::R1, Reg::R10, tmp));
        self.free_slot();
        Ok((lty, rty))
    }

    fn binary(&mut self, op: BinaryOp, lhs: &Expr, rhs: &Expr) -> Result<Ty, String> {
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
                };
                self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, self.ctx_slot));
                self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R0, off));
                Ok(Ty::Uint(8))
            }
            ("sample", [n]) => {
                let rate = self.const_eval(n)?;
                self.emit_sample(rate)
            }
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
            (m, a) => Err(format!("`pkt` has no method `{m}` taking {} argument(s)", a.len())),
        }
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
