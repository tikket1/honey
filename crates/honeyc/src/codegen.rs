//! Stage 3 codegen: compile a detection probe to BPF bytecode.
//!
//! Supported today: `const` (integer literals), `map` (`hash<K, V>` and
//! `array<V>`), `event`, one `tracepoint` probe; `let`, assignment, `if`,
//! `if let Some(x) = map.get(k)`, `return`, `emit`; integer literals, names,
//! nullary builtins, `*ptr`, arithmetic / bitwise / comparison / `&&` / `||`
//! / `!`, `map.get(k)`, `map.insert(k, v)`. That covers `exec.hny` and
//! `exec_burst.hny`.
//!
//! Not yet: `for`, strings beyond `comm()`, `read_user_str`, `as`, signed
//! comparisons. Each reports a clear "not yet" error rather than emitting
//! something the verifier would reject.
//!
//! # How values move
//!
//! Every expression evaluates into `R0`. Locals live on the BPF stack, one
//! 8-byte slot each, addressed as `[R10 - off]`. Binary operators spill the
//! left operand to a scratch slot while the right is computed, then reload it
//! into `R1`. It is not clever, but it is easy to read and the verifier
//! accepts it; register allocation can come later.
//!
//! `R6` is reserved during an `emit` for the ring-buffer record pointer; it
//! is callee-saved so helper calls inside field expressions don't clobber it.
//!
//! # Map references
//!
//! `ld64 rN, map_fd(i)` carries a map *index*, not a real fd. Index 0 is the
//! event ring buffer; user maps follow in declaration order. The loader
//! creates the maps and rewrites each index to the fd it got.

use std::collections::HashMap;

use crate::ast::*;
use crate::bpf::{self, *};
use crate::layout::{layout_event, EventLayout, FieldKind};

// ------------------------------------------------------------------ output

/// A compiled probe plus everything the loader needs to install it.
#[derive(Debug, Clone)]
pub struct Compiled {
    pub bytecode: Vec<u8>,
    pub tracepoint: (String, String),
    /// Ring buffer size in bytes (map index 0).
    pub ringbuf_bytes: u32,
    /// User maps, in index order starting at 1.
    pub maps: Vec<MapSpec>,
    /// Layouts of every declared event (the loader decodes by name).
    pub events: Vec<EventLayout>,
    /// The event this probe emits (the loader prints this one).
    pub event: EventLayout,
    pub license: String,
    /// Bytes of BPF stack the probe uses (must stay ≤ 512).
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

// -------------------------------------------------------------------- types
//
// Just enough type information to pick load/store widths. Stage 4 replaces
// this with a real checker; codegen then consumes its output.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ty {
    Uint(u32), // byte width
    Bool,
    /// Pointer into a map value of this type (from `map.get`).
    ValuePtr(Box<Ty>),
    /// `Option<&V>` straight out of `map.get`, before the null check.
    OptionPtr(Box<Ty>),
}

impl Ty {
    fn from_ast(t: &Type) -> Result<Ty, String> {
        match (t.name.name.as_str(), t.args.as_slice()) {
            ("u8", []) => Ok(Ty::Uint(1)),
            ("u16", []) => Ok(Ty::Uint(2)),
            ("u32", []) => Ok(Ty::Uint(4)),
            ("u64", []) => Ok(Ty::Uint(8)),
            ("bool", []) => Ok(Ty::Bool),
            (other, _) => Err(format!("type `{other}` is not supported in codegen yet")),
        }
    }

    fn size(&self) -> u32 {
        match self {
            Ty::Uint(w) => *w,
            Ty::Bool => 1,
            Ty::ValuePtr(_) | Ty::OptionPtr(_) => 8,
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

struct Cg {
    prog: Prog,
    events: HashMap<String, EventLayout>,
    maps: Vec<MapSpec>,
    map_index: HashMap<String, i32>,
    map_types: HashMap<String, (Ty, Ty)>, // key, value
    consts: HashMap<String, i64>,
    scopes: Vec<HashMap<String, Local>>,
    /// Next free stack offset (positive magnitude; slot is at R10 - off).
    stack_top: i32,
    max_stack: i32,
    exit_label: Label,
}

// -------------------------------------------------------------------- entry

pub fn compile(program: &Program) -> Result<Compiled, String> {
    let mut events = HashMap::new();
    let mut maps = Vec::new();
    let mut map_index = HashMap::new();
    let mut map_types = HashMap::new();
    let mut consts = HashMap::new();
    let mut probe = None;

    for item in &program.items {
        match item {
            Item::Event(e) => {
                events.insert(e.name.name.clone(), layout_event(e)?);
            }
            Item::Const(c) => {
                let v = const_value(&c.value)?;
                consts.insert(c.name.name.clone(), v);
            }
            Item::Map(m) => {
                let (spec, kty, vty) = map_spec(m)?;
                map_index.insert(m.name.name.clone(), (maps.len() as i32) + 1);
                map_types.insert(m.name.name.clone(), (kty, vty));
                maps.push(spec);
            }
            Item::Probe(p) => {
                if probe.is_some() {
                    return Err("only one probe per program is supported yet".into());
                }
                probe = Some(p);
            }
        }
    }
    let probe = probe.ok_or("no probe to compile")?;

    if probe.kind.name != "tracepoint" {
        return Err(format!("only `tracepoint` probes are supported yet, got `{}`", probe.kind.name));
    }
    let [category, name] = probe.args.as_slice() else {
        return Err("tracepoint probe needs exactly two string arguments".into());
    };

    let mut prog = Prog::new();
    let exit_label = prog.new_label();
    let mut cg = Cg {
        prog,
        events,
        maps,
        map_index,
        map_types,
        consts,
        scopes: vec![HashMap::new()],
        stack_top: 0,
        max_stack: 0,
        exit_label,
    };

    let emitted = cg.block(&probe.body, true)?;

    // exit: return 0
    cg.prog.bind(cg.exit_label);
    cg.prog.push(mov64_imm(Reg::R0, 0));
    cg.prog.push(bpf::exit());

    if cg.max_stack > BPF_STACK_LIMIT {
        return Err(format!(
            "probe uses {} bytes of stack, the BPF limit is {BPF_STACK_LIMIT}",
            cg.max_stack
        ));
    }

    let event = emitted.ok_or("probe never emits an event; nothing for the loader to print")?;
    let events: Vec<EventLayout> = cg.events.values().cloned().collect();
    let bytecode = cg.prog.to_bytes()?;

    Ok(Compiled {
        bytecode,
        tracepoint: (category.clone(), name.clone()),
        ringbuf_bytes: 1 << 16,
        maps: cg.maps,
        events,
        event,
        license: "GPL".into(),
        stack_bytes: cg.max_stack as u32,
    })
}

fn const_value(e: &Expr) -> Result<i64, String> {
    match &e.kind {
        ExprKind::Int(n) => Ok(*n as i64),
        ExprKind::Bool(b) => Ok(*b as i64),
        _ => Err("const initialisers must be integer literals for now".into()),
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

// --------------------------------------------------------------- statements

impl Cg {
    // ---- stack -----------------------------------------------------------

    /// Reserve an 8-byte stack slot; returns the offset below R10.
    fn alloc_slot(&mut self) -> i16 {
        self.stack_top += 8;
        self.max_stack = self.max_stack.max(self.stack_top);
        -(self.stack_top as i16)
    }

    fn free_slot(&mut self) {
        self.stack_top -= 8;
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

    /// Pop a scope and release its slots (LIFO, so this is exact).
    fn pop_scope(&mut self) {
        let scope = self.scopes.pop().unwrap();
        for _ in 0..scope.len() {
            self.free_slot();
        }
    }

    // ---- blocks ----------------------------------------------------------

    /// Compile a block. Returns the layout of the event it emits, if any
    /// (`top` blocks must emit exactly one kind so the loader knows what to
    /// print).
    fn block(&mut self, b: &Block, top: bool) -> Result<Option<EventLayout>, String> {
        if !top {
            self.push_scope();
        }
        let mut emitted: Option<EventLayout> = None;
        for s in &b.stmts {
            if let Some(ev) = self.stmt(s)? {
                match &emitted {
                    Some(prev) if prev.name != ev.name => {
                        return Err(format!(
                            "a probe may emit only one event type for now (got `{}` and `{}`)",
                            prev.name, ev.name
                        ));
                    }
                    _ => emitted = Some(ev),
                }
            }
        }
        if !top {
            self.pop_scope();
        }
        Ok(emitted)
    }

    fn stmt(&mut self, s: &Stmt) -> Result<Option<EventLayout>, String> {
        match &s.kind {
            StmtKind::Let { name, ty, value, .. } => {
                let vty = self.expr(value)?; // value in R0
                let ty = match ty {
                    Some(t) => Ty::from_ast(t)?,
                    None => vty,
                };
                let local = self.declare(&name.name, ty);
                self.prog.push(stx_mem(Size::DW, Reg::R10, local.off, Reg::R0));
                Ok(None)
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
                        Ok(None)
                    }
                    ExprKind::Unary { op: UnaryOp::Deref, .. } => {
                        Err("writing through a map pointer (`*p = ...`) is not supported yet; use `map.insert`".into())
                    }
                    _ => Err("invalid assignment target".into()),
                }
            }
            StmtKind::If { cond, then, otherwise } => {
                let else_label = self.prog.new_label();
                let end_label = self.prog.new_label();
                match cond {
                    Cond::Expr(e) => {
                        let then_label = self.prog.new_label();
                        self.cond(e, then_label, else_label)?;
                        self.prog.bind(then_label);
                    }
                    Cond::Let { pattern, value } => {
                        self.if_let_prelude(pattern, value, else_label)?;
                    }
                }
                let mut emitted = self.block(then, false)?;
                if let Cond::Let { pattern, .. } = cond
                    && pattern.binding.is_some() {
                        self.pop_scope(); // the binding's scope
                    }
                if otherwise.is_some() {
                    self.prog.ja_to(end_label);
                }
                self.prog.bind(else_label);
                if let Some(b) = otherwise
                    && let Some(ev) = self.block(b, false)? {
                        emitted = Some(ev);
                    }
                self.prog.bind(end_label);
                Ok(emitted)
            }
            StmtKind::Return(None) => {
                self.prog.ja_to(self.exit_label);
                Ok(None)
            }
            StmtKind::Return(Some(_)) => Err("`return <value>` is not supported; probes return 0".into()),
            StmtKind::Emit { event, fields } => self.emit(event, fields).map(Some),
            StmtKind::Expr(e) => {
                self.expr(e)?;
                Ok(None)
            }
            StmtKind::For { .. } => Err("`for` loops are not supported in codegen yet (stage 3c)".into()),
        }
    }

    /// `if let Some(x) = map.get(k)`: evaluate the lookup, spill the pointer
    /// into a fresh local `x`, and jump to `else_label` when it is null.
    fn if_let_prelude(&mut self, pattern: &Pattern, value: &Expr, else_label: Label) -> Result<(), String> {
        let ty = self.expr(value)?; // R0 = ptr or 0
        let Ty::OptionPtr(inner) = ty else {
            return Err("`if let` only works on the result of `map.get(...)`".into());
        };
        match (pattern.name.name.as_str(), &pattern.binding) {
            ("Some", Some(bind)) => {
                // The binding lives in its own scope so it disappears after
                // the then-block. We spill R0 first, then null-check it; the
                // verifier propagates the check to the spilled copy.
                self.push_scope();
                let local = self.declare(&bind.name, Ty::ValuePtr(inner));
                self.prog.push(stx_mem(Size::DW, Reg::R10, local.off, Reg::R0));
                self.prog.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, else_label);
                Ok(())
            }
            ("None", None) => {
                self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, 0, else_label);
                Ok(())
            }
            _ => Err("pattern must be `Some(name)` or `None`".into()),
        }
    }

    // ---- conditions ------------------------------------------------------

    /// Compile a boolean expression as control flow: jump to `then_label` if
    /// true, `else_label` if false. Short-circuits `&&` / `||`.
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
            ExprKind::Binary { op, lhs, rhs } if compare_op(*op).is_some() => {
                // R1 = lhs, R0 = rhs, then `if R1 op R0 goto then; goto else`.
                self.binary_operands(lhs, rhs)?;
                let jop = compare_op(*op).unwrap();
                self.prog.jmp_reg_to(jop, Reg::R1, Reg::R0, then_label);
                self.prog.ja_to(else_label);
                Ok(())
            }
            _ => {
                // Any other expression: nonzero is true.
                self.expr(e)?;
                self.prog.jmp_imm_to(JmpOp::Ne, Reg::R0, 0, then_label);
                self.prog.ja_to(else_label);
                Ok(())
            }
        }
    }

    // ---- emit ------------------------------------------------------------

    fn emit(&mut self, event: &Ident, fields: &[(Ident, Expr)]) -> Result<EventLayout, String> {
        let layout = self
            .events
            .get(&event.name)
            .cloned()
            .ok_or_else(|| format!("unknown event `{}`", event.name))?;
        if fields.len() != layout.fields.len() {
            return Err(format!(
                "event `{}` has {} fields but `emit` provides {}",
                layout.name,
                layout.fields.len(),
                fields.len()
            ));
        }

        let skip = self.prog.new_label();

        // r0 = bpf_ringbuf_reserve(&ringbuf, size, 0); if !r0 skip
        self.prog.push(ld_map_fd(Reg::R1, RINGBUF_INDEX));
        self.prog.push(mov64_imm(Reg::R2, layout.size as i32));
        self.prog.push(mov64_imm(Reg::R3, 0));
        self.prog.push(call(Helper::RingbufReserve));
        self.prog.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, skip);
        self.prog.push(mov64_reg(Reg::R6, Reg::R0));

        for (fname, value) in fields {
            let fl = layout
                .fields
                .iter()
                .find(|f| f.name == fname.name)
                .ok_or_else(|| format!("event `{}` has no field `{}`", layout.name, fname.name))?;
            let off = i16::try_from(fl.offset).map_err(|_| "field offset too large")?;

            // comm() fills the field in place; everything else is a value.
            if let ExprKind::Call { callee, args } = &value.kind
                && args.is_empty() && matches!(&callee.kind, ExprKind::Ident(n) if n == "comm") {
                    let FieldKind::Str(n) = fl.kind else {
                        return Err("`comm()` must fill a `str<N>` field".into());
                    };
                    self.prog.push(mov64_reg(Reg::R1, Reg::R6));
                    self.prog.push(alu64_imm(AluOp::Add, Reg::R1, off as i32));
                    self.prog.push(mov64_imm(Reg::R2, n as i32));
                    self.prog.push(call(Helper::GetCurrentComm));
                    continue;
                }
            let size = match fl.kind {
                FieldKind::Uint(w) => Ty::Uint(w).mem_size(),
                FieldKind::Bool => Size::B,
                FieldKind::Str(_) => return Err(format!("field `{}`: only `comm()` can fill a string field yet", fname.name)),
            };
            self.expr(value)?;
            self.prog.push(stx_mem(size, Reg::R6, off, Reg::R0));
        }

        // bpf_ringbuf_submit(r6, 0)
        self.prog.push(mov64_reg(Reg::R1, Reg::R6));
        self.prog.push(mov64_imm(Reg::R2, 0));
        self.prog.push(call(Helper::RingbufSubmit));
        self.prog.bind(skip);
        Ok(layout)
    }

    // ---- expressions -----------------------------------------------------

    /// Evaluate `e` into R0. Returns its (approximate) type.
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
            ExprKind::Str(_) => Err("string values are not supported in expressions yet".into()),
            ExprKind::Ident(name) => {
                if let Some(local) = self.lookup(name).cloned() {
                    self.prog.push(ldx_mem(Size::DW, Reg::R0, Reg::R10, local.off));
                    return Ok(local.ty);
                }
                if let Some(v) = self.consts.get(name).copied() {
                    self.load_imm(Reg::R0, v);
                    return Ok(Ty::Uint(8));
                }
                Err(format!("unknown name `{name}`"))
            }
            ExprKind::Unary { op, expr } => match op {
                UnaryOp::Deref => {
                    let ty = self.expr(expr)?;
                    match ty {
                        Ty::ValuePtr(inner) => {
                            self.prog.push(ldx_mem(inner.mem_size(), Reg::R0, Reg::R0, 0));
                            Ok(*inner)
                        }
                        Ty::OptionPtr(_) => Err("map value must be checked with `if let Some(..)` before `*`".into()),
                        _ => Err("`*` applied to a non-pointer".into()),
                    }
                }
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
                    // !x  ==  (x == 0)
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
            ExprKind::Cast { .. } => Err("`as` casts are not supported in codegen yet".into()),
            ExprKind::Call { callee, args } => {
                let name = match &callee.kind {
                    ExprKind::Ident(n) => n.clone(),
                    _ => return Err("only plain builtin calls are supported".into()),
                };
                if !args.is_empty() {
                    return Err(format!("builtin `{name}` with arguments is not supported yet"));
                }
                self.builtin(&name)
            }
            ExprKind::MethodCall { receiver, method, args } => {
                let map = match &receiver.kind {
                    ExprKind::Ident(n) if self.map_index.contains_key(n) => n.clone(),
                    _ => return Err(format!("`.{}()` is only supported on maps", method.name)),
                };
                self.map_method(&map, &method.name, args)
            }
            ExprKind::Field { .. } => Err("field access is not supported in codegen yet".into()),
            ExprKind::Index { .. } => Err("indexing is not supported in codegen yet".into()),
        }
    }

    fn load_imm(&mut self, reg: Reg, v: i64) {
        if let Ok(small) = i32::try_from(v) {
            self.prog.push(mov64_imm(reg, small));
        } else {
            self.prog.push(ld_imm64(reg, v));
        }
    }

    /// Leaves lhs in R1 and rhs in R0.
    fn binary_operands(&mut self, lhs: &Expr, rhs: &Expr) -> Result<Ty, String> {
        let lty = self.expr(lhs)?;
        let tmp = self.alloc_slot();
        self.prog.push(stx_mem(Size::DW, Reg::R10, tmp, Reg::R0));
        self.expr(rhs)?;
        self.prog.push(ldx_mem(Size::DW, Reg::R1, Reg::R10, tmp));
        self.free_slot();
        Ok(lty)
    }

    fn binary(&mut self, op: BinaryOp, lhs: &Expr, rhs: &Expr) -> Result<Ty, String> {
        if matches!(op, BinaryOp::And | BinaryOp::Or) || compare_op(op).is_some() {
            // Materialise a boolean: 1 if the condition holds, else 0.
            let t = self.prog.new_label();
            let f = self.prog.new_label();
            let end = self.prog.new_label();
            let e = Expr { kind: ExprKind::Binary { op, lhs: Box::new(lhs.clone()), rhs: Box::new(rhs.clone()) }, span: lhs.span };
            self.cond(&e, t, f)?;
            self.prog.bind(t);
            self.prog.push(mov64_imm(Reg::R0, 1));
            self.prog.ja_to(end);
            self.prog.bind(f);
            self.prog.push(mov64_imm(Reg::R0, 0));
            self.prog.bind(end);
            return Ok(Ty::Bool);
        }

        let lty = self.binary_operands(lhs, rhs)?; // R1 = lhs, R0 = rhs
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
        // R1 = R1 op R0; R0 = R1
        self.prog.push(alu64_reg(alu, Reg::R1, Reg::R0));
        self.prog.push(mov64_reg(Reg::R0, Reg::R1));
        Ok(lty)
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
                self.prog.push(alu32_reg(AluOp::Mov, Reg::R0, Reg::R0)); // zero-extend low 32
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
            "comm" => Err("`comm()` can only be used directly as an `emit` field value for now".into()),
            other => Err(format!("unknown builtin `{other}()`")),
        }
    }

    fn map_method(&mut self, map: &str, method: &str, args: &[Expr]) -> Result<Ty, String> {
        let idx = self.map_index[map];
        let (kty, vty) = self.map_types[map].clone();
        match (method, args) {
            ("get", [key]) => {
                // key -> stack slot; r1 = map; r2 = &key; call lookup
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
                Ok(Ty::Uint(8)) // helper's return code, usually ignored
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

fn compare_op(op: BinaryOp) -> Option<JmpOp> {
    Some(match op {
        BinaryOp::Eq => JmpOp::Eq,
        BinaryOp::Ne => JmpOp::Ne,
        BinaryOp::Lt => JmpOp::Lt,
        BinaryOp::Le => JmpOp::Le,
        BinaryOp::Gt => JmpOp::Gt,
        BinaryOp::Ge => JmpOp::Ge,
        _ => return None,
    })
}
