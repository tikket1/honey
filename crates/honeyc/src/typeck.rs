//! Stage 4: the verifier-aware type checker.
//!
//! This is the research contribution of honey. The kernel verifier rejects a
//! program for a small, well-known set of reasons: an unbounded loop, a map
//! pointer used before its null check, a read of unknown length, more than
//! 512 bytes of stack. Each of those rules is expressed here as a *type* or
//! *scoping* rule, so that a program that passes this checker is one the
//! verifier accepts, and a program that would be rejected fails here — with
//! a message that points at the offending source line, not at "instruction
//! 213".
//!
//! The rules, and where they live:
//!
//! | verifier rule                     | checker rule                                        |
//! |-----------------------------------|-----------------------------------------------------|
//! | loops must be provably bounded    | `for` bounds are compile-time constants, ≤ 64 iters |
//! | map lookup result may be NULL     | `map.get` is `Option<&V>`; only `if let Some` unwraps|
//! | pointer must not outlive its check| the `Some(x)` binding is scoped to the `if` body    |
//! | reads need a known length         | `read_user_str` only into a declared `str<N>`       |
//! | stack ≤ 512 bytes                 | locals are summed per scope path; overflow is an error|
//! | no in-place writes through ptrs   | `*p = v` is rejected (v1)                            |
//!
//! Everything else is ordinary static typing: unsigned integers of four
//! widths, `bool`, `str<N>`, and no implicit conversions.
//!
//! Output is a list of diagnostics (all errors, not just the first) so a user
//! fixes a file in one pass. On success it reports the stack budget used.

use std::collections::HashMap;

use crate::ast::*;
use crate::btf::{Btf, Resolved};
use crate::token::Span;

// ------------------------------------------------------------------- types

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ty {
    U8,
    U16,
    U32,
    U64,
    /// Signed 64-bit: the type of `retval()`. Compared with signed jumps.
    I64,
    Bool,
    /// Fixed-capacity byte string.
    Str(u32),
    /// The result of `map.get`: maybe a pointer, must be checked.
    Option(Box<Ty>),
    /// A checked pointer into a map value.
    Ref(Box<Ty>),
    /// A kernel pointer to a named struct (from `arg(n)` typed `ptr<S>`).
    KPtr(String),
    /// A kernel pointer to a char: a string address for `read_kernel_str`.
    KCharPtr,
    /// Statements-as-expressions (`map.insert`) produce this.
    Unit,
    /// An integer literal that has not yet picked a width.
    Int,
}

impl Ty {
    pub fn from_ast(t: &Type) -> Result<Ty, String> {
        match (t.name.name.as_str(), t.args.as_slice()) {
            ("u8", []) => Ok(Ty::U8),
            ("u16", []) => Ok(Ty::U16),
            ("u32", []) => Ok(Ty::U32),
            ("u64", []) => Ok(Ty::U64),
            ("i64", []) => Ok(Ty::I64),
            ("bool", []) => Ok(Ty::Bool),
            ("str", [TypeArg::Int(n)]) => {
                if *n == 0 || *n > 256 {
                    Err(format!("`str<{n}>`: capacity must be between 1 and 256"))
                } else {
                    Ok(Ty::Str(*n as u32))
                }
            }
            ("str", _) => Err("`str` needs a capacity, e.g. `str<64>`".into()),
            (name, _) => Err(format!("unknown type `{name}`")),
        }
    }

    pub fn is_int(&self) -> bool {
        matches!(self, Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::I64 | Ty::Int)
    }

    /// Bytes this value occupies on the BPF stack as a local.
    pub fn stack_bytes(&self) -> u32 {
        match self {
            Ty::Str(n) => n.div_ceil(8) * 8,
            Ty::Unit => 0,
            _ => 8,
        }
    }

    /// Largest value a width can hold (for literal range checks).
    fn max_value(&self) -> Option<u64> {
        Some(match self {
            Ty::U8 => u8::MAX as u64,
            Ty::U16 => u16::MAX as u64,
            Ty::U32 => u32::MAX as u64,
            Ty::U64 | Ty::Int => u64::MAX,
            Ty::I64 => i64::MAX as u64,
            _ => return None,
        })
    }
}

impl std::fmt::Display for Ty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ty::U8 => write!(f, "u8"),
            Ty::U16 => write!(f, "u16"),
            Ty::U32 => write!(f, "u32"),
            Ty::U64 => write!(f, "u64"),
            Ty::I64 => write!(f, "i64"),
            Ty::Bool => write!(f, "bool"),
            Ty::Str(n) => write!(f, "str<{n}>"),
            Ty::Option(inner) => write!(f, "Option<&{inner}>"),
            Ty::Ref(inner) => write!(f, "&{inner}"),
            Ty::KPtr(name) => write!(f, "ptr<{name}>"),
            Ty::KCharPtr => write!(f, "ptr<char>"),
            Ty::Unit => write!(f, "()"),
            Ty::Int => write!(f, "{{integer}}"),
        }
    }
}

// ------------------------------------------------------------- diagnostics

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diag {
    pub message: String,
    pub span: Span,
    pub help: Option<String>,
}

/// What a successful check tells the next stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// Peak bytes of BPF stack any probe's locals need.
    pub stack_bytes: u32,
}

/// The BPF stack is 512 bytes. Codegen needs a little for the saved context
/// pointer and spill slots; the rest is the user's.
pub const STACK_LIMIT: u32 = 512;
pub const STACK_RESERVED: u32 = 40;
pub const MAX_UNROLL: i64 = 64;
/// Syscall tracepoints and kprobes expose at most six arguments.
pub const MAX_ARG: i64 = 5;
/// The furthest byte an XDP probe may read; the entry bounds check covers it.
pub const MAX_PKT_BOUND: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeKind {
    Tracepoint,
    Kprobe,
    Kretprobe,
    /// An LSM hook: can observe and can `deny()` the action.
    Lsm,
    /// An XDP program on a network interface: sees raw packets, can `drop()`.
    Xdp,
    /// A uprobe on a userspace function entry.
    Uprobe,
    /// A uretprobe on a userspace function return.
    Uretprobe,
}

// ----------------------------------------------------------------- checker

#[derive(Debug, Clone)]
struct Var {
    ty: Ty,
    mutable: bool,
    /// Compile-time value, for loop variables (used in `byte_at(i)`).
    konst: Option<i64>,
}

#[derive(Default)]
struct Scope {
    vars: HashMap<String, Var>,
    bytes: u32,
}

struct MapInfo {
    key: Ty,
    value: Ty,
}

struct EventInfo {
    fields: Vec<(String, Ty)>,
}

struct Checker<'a> {
    btf: Option<&'a Btf>,
    consts: HashMap<String, (Ty, u64)>,
    maps: HashMap<String, MapInfo>,
    events: HashMap<String, EventInfo>,
    scopes: Vec<Scope>,
    stack_now: u32,
    stack_peak: u32,
    diags: Vec<Diag>,
    /// The kind of the probe whose body is being checked.
    probe_kind: Option<ProbeKind>,
}

pub fn check(program: &Program) -> Result<Checked, Vec<Diag>> {
    check_with_btf(program, None)
}

pub fn check_with_btf(program: &Program, btf: Option<&Btf>) -> Result<Checked, Vec<Diag>> {
    let mut c = Checker {
        btf,
        consts: HashMap::new(),
        maps: HashMap::new(),
        events: HashMap::new(),
        scopes: Vec::new(),
        stack_now: 0,
        stack_peak: 0,
        diags: Vec::new(),
        probe_kind: None,
    };
    let peak = c.program(program);
    if c.diags.is_empty() {
        Ok(Checked { stack_bytes: peak })
    } else {
        Err(c.diags)
    }
}

impl Checker<'_> {
    // ---- diagnostics -----------------------------------------------------

    fn error(&mut self, span: Span, message: impl Into<String>) {
        self.diags.push(Diag { message: message.into(), span, help: None });
    }

    fn error_help(&mut self, span: Span, message: impl Into<String>, help: impl Into<String>) {
        self.diags.push(Diag { message: message.into(), span, help: Some(help.into()) });
    }

    // ---- scopes ----------------------------------------------------------

    fn push_scope(&mut self) {
        self.scopes.push(Scope::default());
    }

    fn pop_scope(&mut self) {
        let s = self.scopes.pop().unwrap();
        self.stack_now -= s.bytes;
    }

    fn declare(&mut self, name: &str, ty: Ty, mutable: bool, konst: Option<i64>) {
        let bytes = ty.stack_bytes();
        self.stack_now += bytes;
        self.stack_peak = self.stack_peak.max(self.stack_now);
        let scope = self.scopes.last_mut().unwrap();
        scope.bytes += bytes;
        scope.vars.insert(name.to_string(), Var { ty, mutable, konst });
    }

    fn lookup(&self, name: &str) -> Option<&Var> {
        self.scopes.iter().rev().find_map(|s| s.vars.get(name))
    }

    // ---- items -----------------------------------------------------------

    fn program(&mut self, p: &Program) -> u32 {
        // Declarations first, so order in the file doesn't matter.
        for item in &p.items {
            match item {
                Item::Const(c) => self.const_decl(c),
                Item::Map(m) => self.map_decl(m),
                Item::Event(e) => self.event_decl(e),
                Item::Probe(_) => {}
            }
        }
        let probes: Vec<&ProbeDecl> = p
            .items
            .iter()
            .filter_map(|i| if let Item::Probe(p) = i { Some(p) } else { None })
            .collect();
        if probes.is_empty() {
            self.error(Span::new(0, 0), "program has no `probe`");
        }
        // Each probe is its own BPF program with its own 512-byte stack.
        let mut peak = 0;
        for pr in probes {
            self.stack_now = 0;
            self.stack_peak = 0;
            self.probe(pr);
            peak = peak.max(self.stack_peak);
        }
        peak
    }

    fn const_decl(&mut self, c: &ConstDecl) {
        let ty = match Ty::from_ast(&c.ty) {
            Ok(t) => t,
            Err(m) => return self.error(c.ty.span, m),
        };
        if !ty.is_int() && ty != Ty::Bool {
            return self.error(c.ty.span, format!("const `{}`: only integers and bool can be constants", c.name.name));
        }
        let value = match &c.value.kind {
            ExprKind::Int(n) => *n,
            ExprKind::Bool(b) => *b as u64,
            _ => {
                return self.error_help(
                    c.value.span,
                    "const initialiser must be a literal",
                    "constants are baked into the bytecode, so they have to be known here",
                );
            }
        };
        if let Some(max) = ty.max_value()
            && value > max
        {
            return self.error(c.value.span, format!("{value} does not fit in `{ty}`"));
        }
        self.consts.insert(c.name.name.clone(), (ty, value));
    }

    fn map_decl(&mut self, m: &MapDecl) {
        let scalar = |t: &Type| -> Result<Ty, String> {
            let ty = Ty::from_ast(t)?;
            if ty.is_int() || ty == Ty::Bool {
                Ok(ty)
            } else {
                Err(format!("map keys and values must be integers or bool in v1, not `{ty}`"))
            }
        };
        let info = match (m.kind.name.as_str(), m.args.as_slice()) {
            ("hash", [k, v]) => match (scalar(k), scalar(v)) {
                (Ok(key), Ok(value)) => MapInfo { key, value },
                (Err(e), _) => return self.error(k.span, e),
                (_, Err(e)) => return self.error(v.span, e),
            },
            ("array", [v]) => match scalar(v) {
                Ok(value) => MapInfo { key: Ty::U32, value },
                Err(e) => return self.error(v.span, e),
            },
            (kind, _) => {
                return self.error_help(
                    m.kind.span,
                    format!("unknown map kind `{kind}`"),
                    "use `hash<K, V>` or `array<V>`",
                );
            }
        };
        if m.capacity == 0 {
            self.error(m.span, "map capacity must be at least 1");
        }
        self.maps.insert(m.name.name.clone(), info);
    }

    fn event_decl(&mut self, e: &EventDecl) {
        let mut fields = Vec::new();
        for f in &e.fields {
            match Ty::from_ast(&f.ty) {
                Ok(ty) if ty.is_int() || ty == Ty::Bool || matches!(ty, Ty::Str(_)) => {
                    if fields.iter().any(|(n, _)| n == &f.name.name) {
                        self.error(f.name.span, format!("duplicate field `{}`", f.name.name));
                    }
                    fields.push((f.name.name.clone(), ty));
                }
                Ok(ty) => self.error(f.ty.span, format!("event fields must be integers, bool or str<N>, not `{ty}`")),
                Err(m) => self.error(f.ty.span, m),
            }
        }
        self.events.insert(e.name.name.clone(), EventInfo { fields });
    }

    fn probe(&mut self, p: &ProbeDecl) {
        let kind = match (p.kind.name.as_str(), p.args.len()) {
            ("tracepoint", 2) => Some(ProbeKind::Tracepoint),
            ("tracepoint", _) => {
                self.error(p.span, "`tracepoint` takes two string arguments: category and name");
                None
            }
            ("kprobe", 1) => Some(ProbeKind::Kprobe),
            ("kretprobe", 1) => Some(ProbeKind::Kretprobe),
            ("lsm", 1) => Some(ProbeKind::Lsm),
            ("xdp", 1) => Some(ProbeKind::Xdp),
            ("uprobe", 1) => Some(ProbeKind::Uprobe),
            ("uretprobe", 1) => Some(ProbeKind::Uretprobe),
            ("uprobe" | "uretprobe", _) => {
                self.error(p.span, format!("`{}` takes one string argument: `\"/path/to/binary:symbol\"`", p.kind.name));
                None
            }
            ("xdp", _) => {
                self.error(p.span, "`xdp` takes one string argument: the interface name, e.g. `xdp(\"eth0\")`");
                None
            }
            ("kprobe" | "kretprobe", _) => {
                self.error(p.span, format!("`{}` takes one string argument: the kernel function name", p.kind.name));
                None
            }
            ("lsm", _) => {
                self.error(p.span, "`lsm` takes one string argument: the hook name, e.g. `lsm(\"file_open\")`");
                None
            }
            (other, _) => {
                self.error_help(
                    p.kind.span,
                    format!("unsupported probe kind `{other}`"),
                    "use `tracepoint`, `kprobe`, `kretprobe`, `lsm`, `xdp`, `uprobe`, or `uretprobe`",
                );
                None
            }
        };
        if p.args.iter().any(|a| a.is_empty()) {
            self.error(p.span, "probe target must not be empty");
        }
        if matches!(kind, Some(ProbeKind::Uprobe) | Some(ProbeKind::Uretprobe))
            && let [target] = p.args.as_slice()
            && !target.contains(':')
        {
            self.error_help(
                p.span,
                "uprobe target must be `path:symbol`",
                "for example `uprobe(\"/lib/x86_64-linux-gnu/libc.so.6:getenv\")`",
            );
        }
        self.probe_kind = kind;
        self.push_scope();
        self.block(&p.body);
        self.pop_scope();
        self.probe_kind = None;

        let budget = STACK_LIMIT - STACK_RESERVED;
        if self.stack_peak > budget {
            self.error_help(
                p.body.span,
                format!(
                    "probe needs {} bytes of stack for its locals; the BPF limit leaves {budget}",
                    self.stack_peak
                ),
                "shrink a `str<N>` buffer or narrow a scope",
            );
        }
    }

    // ---- statements ------------------------------------------------------

    fn block(&mut self, b: &Block) {
        for s in &b.stmts {
            self.stmt(s);
        }
    }

    fn scoped_block(&mut self, b: &Block) {
        self.push_scope();
        self.block(b);
        self.pop_scope();
    }

    fn stmt(&mut self, s: &Stmt) {
        match &s.kind {
            StmtKind::Let { mutable, name, ty, value } => self.let_stmt(*mutable, name, ty.as_ref(), value),
            StmtKind::Assign { target, value } => self.assign(target, value),
            StmtKind::If { cond, then, otherwise } => {
                match cond {
                    Cond::Expr(e) => {
                        let t = self.expr(e);
                        if t != Ty::Bool {
                            self.error(e.span, format!("`if` condition must be `bool`, found `{t}`"));
                        }
                        self.scoped_block(then);
                    }
                    Cond::Let { pattern, value } => {
                        let t = self.expr(value);
                        self.push_scope();
                        match t {
                            Ty::Option(inner) => match (pattern.name.name.as_str(), &pattern.binding) {
                                ("Some", Some(b)) => {
                                    // The checked pointer exists only inside this block.
                                    self.declare(&b.name, Ty::Ref(inner), false, None);
                                }
                                ("None", None) => {}
                                ("Some", None) => self.error(pattern.span, "`Some` needs a binding: `Some(name)`"),
                                ("None", Some(_)) => self.error(pattern.span, "`None` takes no binding"),
                                (other, _) => self.error(pattern.span, format!("unknown pattern `{other}`; use `Some(x)` or `None`")),
                            },
                            other => self.error_help(
                                value.span,
                                format!("`if let` needs an `Option<&V>` from `map.get`, found `{other}`"),
                                "only map lookups can be `None`",
                            ),
                        }
                        self.block(then);
                        self.pop_scope();
                    }
                }
                if let Some(b) = otherwise {
                    self.scoped_block(b);
                }
            }
            StmtKind::For { var, start, end, body } => self.for_stmt(var, start, end, body),
            StmtKind::Emit { event, fields } => self.emit(event, fields, s.span),
            StmtKind::Return(None) => {}
            StmtKind::Return(Some(e)) => self.error(e.span, "probes always return 0; use a bare `return;`"),
            StmtKind::Expr(e) => {
                let t = self.expr(e);
                if !matches!(e.kind, ExprKind::MethodCall { .. }) && t != Ty::Unit {
                    self.error(e.span, "expression statement has no effect");
                }
            }
        }
    }

    fn let_stmt(&mut self, mutable: bool, name: &Ident, ty: Option<&Type>, value: &Expr) {
        // Strings: `let s: str<N> = read_user_str(p);` / `read_kernel_str(p);`
        // — the annotation *is* the read bound, which is why it is mandatory.
        let reader = if is_call_to(value, "read_user_str") {
            Some(("read_user_str", false))
        } else if is_call_to(value, "read_kernel_str") {
            Some(("read_kernel_str", true))
        } else {
            None
        };
        if let Some((fname, kernel)) = reader {
            let Some(t) = ty else {
                self.error_help(
                    value.span,
                    format!("`{fname}` needs a bounded destination"),
                    format!("write `let {}: str<N> = {fname}(...)` so the read has a known length", name.name),
                );
                self.declare(&name.name, Ty::Unit, mutable, None);
                return;
            };
            let declared = match Ty::from_ast(t) {
                Ok(t) => t,
                Err(m) => return self.error(t.span, m),
            };
            let Ty::Str(_) = declared else {
                return self.error(t.span, format!("`{fname}` produces a `str<N>`, not `{declared}`"));
            };
            let ExprKind::Call { args, .. } = &value.kind else { unreachable!() };
            match args.as_slice() {
                [p] => {
                    let pt = self.expr(p);
                    let ok = if kernel {
                        // a kernel char pointer, a kernel struct pointer, or a raw address
                        matches!(pt, Ty::KCharPtr | Ty::KPtr(_)) || pt == Ty::U64 || pt == Ty::Int
                    } else {
                        pt == Ty::U64 || pt == Ty::Int
                    };
                    if !ok {
                        let want = if kernel { "a kernel pointer" } else { "a user pointer (`u64`)" };
                        self.error(p.span, format!("`{fname}` takes {want}, found `{pt}`"));
                    }
                }
                _ => self.error(value.span, format!("`{fname}` takes exactly one argument")),
            }
            self.declare(&name.name, declared, mutable, None);
            return;
        }

        // Kernel struct pointers: `let f: ptr<S> = arg(n);` (or from another
        // pointer). Needs BTF to know that `S` is a real kernel struct.
        if let Some(t) = ty
            && t.name.name == "ptr"
        {
            let target = self.ptr_target(t);
            let at = self.expr(value);
            if at != Ty::U64 && at != Ty::Int && !matches!(at, Ty::KPtr(_) | Ty::KCharPtr) {
                self.error(value.span, format!("`ptr<...>` must come from an argument or another pointer, found `{at}`"));
            }
            match target {
                Some(sname) => self.declare(&name.name, Ty::KPtr(sname), mutable, None),
                None => self.declare(&name.name, Ty::Unit, mutable, None),
            }
            return;
        }

        let before = self.diags.len();
        let actual = self.expr(value);
        let value_had_errors = self.diags.len() > before;
        let ty = match ty {
            Some(t) => match Ty::from_ast(t) {
                Ok(declared) => {
                    self.expect(&declared, &actual, value.span);
                    self.literal_fits(&declared, value);
                    declared
                }
                Err(m) => {
                    self.error(t.span, m);
                    actual
                }
            },
            None => match actual {
                Ty::Int => Ty::U64,
                Ty::Unit => {
                    if !value_had_errors {
                        self.error(value.span, "this expression has no value to bind");
                    }
                    Ty::Unit
                }
                t => t,
            },
        };
        if let Ty::Str(_) = ty {
            self.error_help(value.span, "strings can only come from `read_user_str`", "declare `let s: str<N> = read_user_str(ptr);`");
        }
        self.declare(&name.name, ty, mutable, None);
    }

    fn assign(&mut self, target: &Expr, value: &Expr) {
        match &target.kind {
            ExprKind::Ident(n) => {
                let Some(var) = self.lookup(n).cloned() else {
                    return self.error(target.span, format!("unknown variable `{n}`"));
                };
                if !var.mutable {
                    self.error_help(
                        target.span,
                        format!("cannot assign to `{n}`: it is not mutable"),
                        format!("declare it with `let mut {n} = ...`"),
                    );
                }
                let vt = self.expr(value);
                self.expect(&var.ty, &vt, value.span);
                self.literal_fits(&var.ty, value);
            }
            ExprKind::Unary { op: UnaryOp::Deref, .. } => {
                self.error_help(
                    target.span,
                    "writing through a map pointer is not supported in v1",
                    "use `map.insert(key, value)` to update the map",
                );
                self.expr(value);
            }
            _ => self.error(target.span, "invalid assignment target"),
        }
    }

    fn for_stmt(&mut self, var: &Ident, start: &Expr, end: &Expr, body: &Block) {
        let lo = self.const_eval(start);
        let hi = self.const_eval(end);
        let (Some(lo), Some(hi)) = (lo, hi) else {
            // const_eval already reported which bound is not constant.
            return;
        };
        if hi < lo {
            self.error(end.span, format!("loop runs from {lo} to {hi}: end is before start"));
        } else if hi - lo > MAX_UNROLL {
            self.error_help(
                end.span,
                format!("loop would run {} times; the limit is {MAX_UNROLL}", hi - lo),
                "the verifier needs every loop to be provably bounded; honey unrolls them",
            );
        }
        self.push_scope();
        // The loop variable is a constant inside the body: no size on stack.
        self.scopes.last_mut().unwrap().vars.insert(
            var.name.clone(),
            Var { ty: Ty::U64, mutable: false, konst: Some(lo) },
        );
        self.block(body);
        self.pop_scope();
    }

    fn emit(&mut self, event: &Ident, fields: &[(Ident, Expr)], span: Span) {
        let Some(info) = self.events.get(&event.name) else {
            return self.error(event.span, format!("unknown event `{}`", event.name));
        };
        let declared: Vec<(String, Ty)> = info.fields.clone();

        let mut seen: Vec<&str> = Vec::new();
        for (fname, value) in fields {
            if seen.contains(&fname.name.as_str()) {
                self.error(fname.span, format!("field `{}` given twice", fname.name));
                continue;
            }
            seen.push(&fname.name);
            let Some((_, fty)) = declared.iter().find(|(n, _)| n == &fname.name) else {
                self.error(fname.span, format!("event `{}` has no field `{}`", event.name, fname.name));
                self.expr(value);
                continue;
            };
            // `comm()` is the one builtin that produces a string.
            if is_call_to(value, "comm") {
                if !matches!(fty, Ty::Str(_)) {
                    self.error(value.span, format!("`comm()` is a string; field `{}` is `{fty}`", fname.name));
                }
                continue;
            }
            let vt = self.expr(value);
            self.expect(fty, &vt, value.span);
            self.literal_fits(fty, value);
        }
        for (n, _) in &declared {
            if !seen.contains(&n.as_str()) {
                self.error_help(
                    span,
                    format!("`emit {}` is missing field `{n}`", event.name),
                    "every field of the event must be set",
                );
            }
        }
    }

    // ---- expressions -----------------------------------------------------

    /// An integer literal must fit the width it is being used at.
    fn literal_fits(&mut self, expected: &Ty, e: &Expr) {
        if let ExprKind::Int(n) = &e.kind
            && let Some(max) = expected.max_value()
            && *n > max
        {
            self.error(e.span, format!("{n} does not fit in `{expected}`"));
        }
    }

    /// Check that `actual` can be used where `expected` is required.
    fn expect(&mut self, expected: &Ty, actual: &Ty, span: Span) {
        if !compatible(expected, actual) {
            let help = if expected.is_int() && actual.is_int() {
                Some("integer widths must match exactly; honey has no implicit conversions".to_string())
            } else if let (Ty::Ref(_), _) = (expected, actual) {
                None
            } else if let (_, Ty::Option(_)) = (expected, actual) {
                Some("check the lookup first: `if let Some(v) = map.get(key) { ... }`".to_string())
            } else {
                None
            };
            self.diags.push(Diag {
                message: format!("mismatched types: expected `{expected}`, found `{actual}`"),
                span,
                help,
            });
        }
    }

    /// Validate `ptr<S>` and return the struct name, or report and return None.
    fn ptr_target(&mut self, t: &Type) -> Option<String> {
        let name = match t.args.as_slice() {
            [TypeArg::Type(inner)] if inner.args.is_empty() => inner.name.name.clone(),
            _ => {
                self.error_help(t.span, "`ptr<...>` needs a struct name", "for example `ptr<file>` or `ptr<task_struct>`");
                return None;
            }
        };
        let Some(btf) = self.btf else {
            self.error_help(
                t.span,
                "reading kernel struct fields needs the kernel's type information",
                "pass `--btf /path/to/vmlinux.btf` (export it with `linux/export-btf`)",
            );
            return None;
        };
        if !btf.is_struct(&name) {
            self.error(t.span, format!("`{name}` is not a kernel struct in the provided BTF"));
            return None;
        }
        Some(name)
    }

    /// Type of `base.field` where `base` is a kernel struct pointer.
    fn field_type(&mut self, struct_name: &str, field: &Ident) -> Ty {
        let Some(btf) = self.btf else {
            self.error(field.span, "kernel field access needs `--btf`");
            return Ty::Unit;
        };
        let Some(member) = btf.member(struct_name, &field.name) else {
            self.error(field.span, format!("`struct {struct_name}` has no field `{}`", field.name));
            return Ty::Unit;
        };
        match btf.resolve(member.type_id) {
            Resolved::Int { bytes, .. } => match bytes {
                1 => Ty::U8,
                2 => Ty::U16,
                4 => Ty::U32,
                _ => Ty::U64,
            },
            Resolved::Struct { name } => Ty::KPtr(name),
            Resolved::PtrToStruct { name } => Ty::KPtr(name),
            Resolved::PtrToChar => Ty::KCharPtr,
            Resolved::PtrToOther => Ty::U64,
            Resolved::Other => {
                self.error_help(
                    field.span,
                    format!("field `{}` has a type honey can't read yet (array, enum, or function pointer)", field.name),
                    "read a scalar, an embedded struct, or a pointer field instead",
                );
                Ty::Unit
            }
        }
    }

    fn expr(&mut self, e: &Expr) -> Ty {
        match &e.kind {
            ExprKind::Int(_) => Ty::Int,
            ExprKind::Bool(_) => Ty::Bool,
            ExprKind::Str(_) => {
                self.error_help(e.span, "string literals can only be used as `starts_with` arguments in v1", "there is no string type you can hold in a variable except `str<N>` from `read_user_str`");
                Ty::Unit
            }
            ExprKind::Ident(name) => {
                if let Some(v) = self.lookup(name) {
                    return v.ty.clone();
                }
                if let Some((t, _)) = self.consts.get(name) {
                    return t.clone();
                }
                if self.maps.contains_key(name) {
                    self.error_help(e.span, format!("`{name}` is a map, not a value"), "use `.get(key)` or `.insert(key, value)`");
                    return Ty::Unit;
                }
                self.error(e.span, format!("unknown name `{name}`"));
                Ty::Unit
            }
            ExprKind::Unary { op, expr } => {
                let t = self.expr(expr);
                match op {
                    UnaryOp::Deref => match t {
                        Ty::Ref(inner) => *inner,
                        Ty::Option(inner) => {
                            self.error_help(
                                e.span,
                                format!("cannot dereference `Option<&{inner}>`: the lookup may have found nothing"),
                                "check it first: `if let Some(v) = map.get(key) { ... *v ... }`",
                            );
                            *inner
                        }
                        other => {
                            if other != Ty::Unit {
                                self.error(e.span, format!("cannot dereference `{other}`"));
                            }
                            Ty::Unit
                        }
                    },
                    UnaryOp::Not => {
                        if t != Ty::Bool && t != Ty::Unit {
                            self.error(e.span, format!("`!` needs a `bool`, found `{t}`"));
                        }
                        Ty::Bool
                    }
                    UnaryOp::Neg | UnaryOp::BitNot => {
                        if !t.is_int() && t != Ty::Unit {
                            self.error(e.span, format!("`{}` needs an integer, found `{t}`", op.symbol()));
                        }
                        t
                    }
                }
            }
            ExprKind::Binary { op, lhs, rhs } => self.binary(*op, lhs, rhs, e.span),
            ExprKind::Cast { expr, ty } => {
                self.expr(expr);
                self.error_help(e.span, "`as` casts are not supported in v1", format!("declare the value with the width you need, e.g. `let x: {} = ...`", crate::pretty::ty(ty)));
                Ty::from_ast(ty).unwrap_or(Ty::Unit)
            }
            ExprKind::Call { callee, args } => self.call(callee, args, e.span),
            ExprKind::MethodCall { receiver, method, args } => self.method(receiver, method, args, e.span),
            ExprKind::Field { expr, field } => {
                let base = self.expr(expr);
                match base {
                    Ty::KPtr(name) => self.field_type(&name, field),
                    Ty::Unit => Ty::Unit,
                    other => {
                        self.error_help(
                            e.span,
                            format!("`.{}` needs a kernel struct pointer, found `{other}`", field.name),
                            "get one with `let p: ptr<Struct> = arg(n);`",
                        );
                        Ty::Unit
                    }
                }
            }
            ExprKind::Index { .. } => {
                self.error_help(e.span, "indexing is not supported in v1", "use `map.get(key)` for maps and `s.byte_at(i)` for strings");
                Ty::Unit
            }
        }
    }

    /// How an operand takes part in a string comparison, decided without
    /// evaluating it (a bare literal is an error everywhere else).
    fn str_side(&self, e: &Expr) -> StrSide {
        match &e.kind {
            ExprKind::Str(lit) => StrSide::Lit(lit.len() as u32),
            ExprKind::Ident(n) => match self.lookup(n).map(|v| v.ty.clone()) {
                Some(Ty::Str(cap)) => StrSide::Local(cap),
                _ => StrSide::No,
            },
            _ => StrSide::No,
        }
    }

    fn binary(&mut self, op: BinaryOp, lhs: &Expr, rhs: &Expr, span: Span) -> Ty {
        // String comparisons: `s == "lit"`, `s != t`. Only `==` / `!=`.
        let (ls, rs) = (self.str_side(lhs), self.str_side(rhs));
        if ls != StrSide::No || rs != StrSide::No {
            if !matches!(op, BinaryOp::Eq | BinaryOp::Ne) {
                self.error_help(span, format!("strings do not support `{}`", op.symbol()), "strings can only be compared with `==` and `!=`, or tested with `starts_with`");
                return Ty::Bool;
            }
            match (ls, rs) {
                (StrSide::Lit(_), StrSide::Lit(_)) => {
                    self.error(span, "comparing two string literals; compare a `str<N>` variable with a literal");
                }
                (StrSide::Local(cap), StrSide::Lit(len)) | (StrSide::Lit(len), StrSide::Local(cap)) => {
                    if len > cap {
                        self.error_help(
                            span,
                            format!("this literal is {len} bytes but the string is only `str<{cap}>`; they can never be equal"),
                            "enlarge the `str<N>` or shorten the literal",
                        );
                    }
                }
                (StrSide::Local(_), StrSide::Local(_)) => {}
                (StrSide::Local(cap), StrSide::No) | (StrSide::No, StrSide::Local(cap)) => {
                    let other = if ls == StrSide::No { self.expr(lhs) } else { self.expr(rhs) };
                    if other != Ty::Unit {
                        self.error(span, format!("cannot compare `str<{cap}>` with `{other}`"));
                    }
                }
                (StrSide::Lit(_), StrSide::No) | (StrSide::No, StrSide::Lit(_)) => {
                    let other = if ls == StrSide::No { self.expr(lhs) } else { self.expr(rhs) };
                    if other != Ty::Unit {
                        self.error_help(span, format!("cannot compare a string literal with `{other}`"), "only a `str<N>` variable can be compared with a literal");
                    }
                }
                (StrSide::No, StrSide::No) => unreachable!(),
            }
            return Ty::Bool;
        }

        let l = self.expr(lhs);
        let r = self.expr(rhs);
        // Errors in operands already reported; don't cascade.
        if l == Ty::Unit || r == Ty::Unit {
            return if matches!(op, BinaryOp::And | BinaryOp::Or | BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge) { Ty::Bool } else { Ty::Unit };
        }
        match op {
            BinaryOp::And | BinaryOp::Or => {
                if l != Ty::Bool {
                    self.error(lhs.span, format!("`{}` needs `bool` operands, found `{l}`", op.symbol()));
                }
                if r != Ty::Bool {
                    self.error(rhs.span, format!("`{}` needs `bool` operands, found `{r}`", op.symbol()));
                }
                Ty::Bool
            }
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                if !compatible(&l, &r) && !compatible(&r, &l) {
                    self.error_help(span, format!("cannot compare `{l}` with `{r}`"), "both sides must have the same type");
                } else if !(l.is_int() || l == Ty::Bool) {
                    self.error(span, format!("cannot compare values of type `{l}`"));
                }
                Ty::Bool
            }
            _ => {
                if !l.is_int() {
                    self.error(lhs.span, format!("`{}` needs integer operands, found `{l}`", op.symbol()));
                    return Ty::Unit;
                }
                if !r.is_int() {
                    self.error(rhs.span, format!("`{}` needs integer operands, found `{r}`", op.symbol()));
                    return Ty::Unit;
                }
                match (&l, &r) {
                    (Ty::Int, t) | (t, Ty::Int) => t.clone(),
                    (a, b) if a == b => a.clone(),
                    (a, b) => {
                        self.error_help(span, format!("mismatched integer widths: `{a}` {} `{b}`", op.symbol()), "honey has no implicit conversions; give both sides the same declared type");
                        a.clone()
                    }
                }
            }
        }
    }

    fn call(&mut self, callee: &Expr, args: &[Expr], span: Span) -> Ty {
        let ExprKind::Ident(name) = &callee.kind else {
            self.error(callee.span, "only builtins can be called");
            return Ty::Unit;
        };
        if self.probe_kind == Some(ProbeKind::Xdp)
            && matches!(name.as_str(), "pid" | "tgid" | "tid" | "uid" | "gid" | "comm" | "arg" | "retval")
        {
            self.error_help(
                span,
                format!("`{name}()` is not available in an `xdp` probe: a packet has no process context"),
                "use `pkt.u8/u16/u32(offset)`, `pkt.len()`, and `ktime()` here",
            );
            for a in args {
                self.expr(a);
            }
            return if name == "comm" { Ty::Str(16) } else { Ty::U64 };
        }
        match (name.as_str(), args) {
            ("pid" | "tgid" | "tid" | "uid" | "gid", []) => Ty::U32,
            ("ktime", []) => Ty::U64,
            ("comm", []) => {
                self.error_help(span, "`comm()` can only be used directly as an `emit` field value", "e.g. `emit Exec { comm: comm() }` with `comm: str<16>` in the event");
                Ty::Str(16)
            }
            ("arg", [idx]) => {
                if matches!(self.probe_kind, Some(ProbeKind::Kretprobe) | Some(ProbeKind::Uretprobe)) {
                    self.error_help(
                        span,
                        "`arg()` is not available in a return probe: the arguments are gone by the time the function returns",
                        "record what you need in the entry probe and share it through a map keyed by `tid()`",
                    );
                }
                match self.const_eval(idx) {
                    Some(n) if (0..=MAX_ARG).contains(&n) => {}
                    Some(n) => self.error(idx.span, format!("`arg({n})`: probes expose arguments 0 to {MAX_ARG}")),
                    None => {}
                }
                Ty::U64
            }
            ("retval", []) => {
                if !matches!(self.probe_kind, Some(ProbeKind::Kretprobe) | Some(ProbeKind::Uretprobe)) {
                    self.error_help(
                        span,
                        "`retval()` is only available in a return probe",
                        "a return value only exists when the function returns; use `kretprobe(\"fn\")` or `uretprobe(\"path:sym\")`",
                    );
                }
                Ty::I64
            }
            ("sample", [n]) => {
                match self.const_eval(n) {
                    Some(v) if v >= 1 => {}
                    Some(v) => self.error(n.span, format!("`sample({v})`: the rate must be at least 1")),
                    None => {}
                }
                Ty::Bool
            }
            ("sample", _) => {
                self.error(span, "`sample(N)` takes one constant rate");
                Ty::Unit
            }
            ("read_user_str" | "read_kernel_str", _) => {
                self.error_help(span, format!("`{name}` must initialise a bounded string"), format!("write `let s: str<N> = {name}(ptr);`"));
                Ty::Unit
            }
            ("drop" | "pass", []) => {
                if self.probe_kind != Some(ProbeKind::Xdp) {
                    self.error_help(
                        span,
                        format!("`{name}()` is only available in an `xdp` probe"),
                        "only an XDP program decides a packet's fate; use `probe xdp(\"iface\") {{ ... }}`",
                    );
                }
                Ty::Unit
            }
            ("drop" | "pass", _) => {
                self.error(span, format!("`{name}()` takes no arguments"));
                Ty::Unit
            }
            ("deny" | "allow", []) => {
                if self.probe_kind != Some(ProbeKind::Lsm) {
                    self.error_help(
                        span,
                        format!("`{name}()` is only available in an `lsm` probe"),
                        "only an LSM hook can allow or deny an action; use `probe lsm(\"hook\") {{ ... }}`",
                    );
                }
                Ty::Unit
            }
            ("deny" | "allow", _) => {
                self.error(span, format!("`{name}()` takes no arguments"));
                Ty::Unit
            }
            ("pid" | "tgid" | "tid" | "uid" | "gid" | "ktime" | "arg" | "retval", _) => {
                self.error(span, format!("wrong number of arguments to `{name}()`"));
                for a in args {
                    self.expr(a);
                }
                Ty::Unit
            }
            (other, _) => {
                self.error(callee.span, format!("unknown builtin `{other}`"));
                for a in args {
                    self.expr(a);
                }
                Ty::Unit
            }
        }
    }

    fn method(&mut self, receiver: &Expr, method: &Ident, args: &[Expr], span: Span) -> Ty {
        let ExprKind::Ident(rname) = &receiver.kind else {
            self.error(receiver.span, "methods can only be called on maps and strings");
            return Ty::Unit;
        };

        // The packet view, only in xdp probes.
        if rname == "pkt" && self.lookup("pkt").is_none() {
            if self.probe_kind != Some(ProbeKind::Xdp) {
                self.error_help(span, "`pkt` is only available in an `xdp` probe", "packets exist only in `probe xdp(\"iface\")`");
                for a in args {
                    self.expr(a);
                }
                return Ty::Unit;
            }
            return match (method.name.as_str(), args) {
                ("len", []) => Ty::U32,
                ("u8" | "u16" | "u32", [off]) => {
                    let width: u32 = match method.name.as_str() {
                        "u8" => 1,
                        "u16" => 2,
                        _ => 4,
                    };
                    match self.const_eval_global(off) {
                        Some(o) if o < 0 => self.error(off.span, "packet offset must not be negative"),
                        Some(o) if o as u32 + width > MAX_PKT_BOUND => self.error_help(
                            off.span,
                            format!("packet read at offset {o} ends past {MAX_PKT_BOUND} bytes, the most an XDP probe may inspect"),
                            "honey checks the packet is at least that long once, on entry; keep reads within the first 256 bytes",
                        ),
                        _ => {}
                    }
                    match width {
                        1 => Ty::U8,
                        2 => Ty::U16,
                        _ => Ty::U32,
                    }
                }
                ("u8" | "u16" | "u32", _) => {
                    self.error(span, format!("`pkt.{}` takes one constant offset", method.name));
                    Ty::Unit
                }
                (m, _) => {
                    self.error(method.span, format!("`pkt` has no method `{m}`; use `u8(off)`, `u16(off)`, `u32(off)`, or `len()`"));
                    Ty::Unit
                }
            };
        }

        // Strings.
        if let Some(var) = self.lookup(rname).cloned() {
            let Ty::Str(cap) = var.ty else {
                self.error(span, format!("`{rname}` is a `{}`, which has no methods", var.ty));
                return Ty::Unit;
            };
            return match (method.name.as_str(), args) {
                ("starts_with", [arg]) => {
                    if let ExprKind::Str(lit) = &arg.kind {
                        if lit.len() as u32 > cap {
                            self.error(arg.span, format!("prefix is {} bytes but `{rname}` is only `str<{cap}>`", lit.len()));
                        }
                    } else {
                        self.error(arg.span, "`starts_with` takes a string literal");
                    }
                    Ty::Bool
                }
                ("byte_at", [arg]) => {
                    match self.const_eval(arg) {
                        Some(i) if i >= 0 && (i as u32) < cap => {}
                        Some(i) => self.error_help(arg.span, format!("`byte_at({i})` is outside `str<{cap}>`"), "the index must be a constant below the string's capacity so the read is bounded"),
                        None => {}
                    }
                    Ty::U8
                }
                (m, _) => {
                    self.error(method.span, format!("string has no method `{m}`; try `starts_with(\"...\")` or `byte_at(i)`"));
                    Ty::Unit
                }
            };
        }

        // Maps.
        let Some(info) = self.maps.get(rname) else {
            self.error(receiver.span, format!("unknown map or string `{rname}`"));
            for a in args {
                self.expr(a);
            }
            return Ty::Unit;
        };
        let (key, value) = (info.key.clone(), info.value.clone());
        match (method.name.as_str(), args) {
            ("get", [k]) => {
                let kt = self.expr(k);
                self.expect(&key, &kt, k.span);
                self.literal_fits(&key, k);
                Ty::Option(Box::new(value))
            }
            ("insert", [k, v]) => {
                let kt = self.expr(k);
                self.expect(&key, &kt, k.span);
                self.literal_fits(&key, k);
                let vt = self.expr(v);
                self.expect(&value, &vt, v.span);
                self.literal_fits(&value, v);
                Ty::Unit
            }
            ("delete", [k]) => {
                let kt = self.expr(k);
                self.expect(&key, &kt, k.span);
                self.literal_fits(&key, k);
                Ty::Unit
            }
            (m, a) => {
                self.error(method.span, format!("map has no method `{m}` with {} argument(s); use `get(k)`, `insert(k, v)`, `delete(k)`", a.len()));
                for x in a {
                    self.expr(x);
                }
                Ty::Unit
            }
        }
    }

    /// Like `const_eval` but without loop variables: for packet offsets, which
    /// must be fixed so the single entry bounds check can cover them all.
    fn const_eval_global(&mut self, e: &Expr) -> Option<i64> {
        match &e.kind {
            ExprKind::Ident(name) if self.lookup(name).is_some() => {
                self.error_help(
                    e.span,
                    format!("packet offset `{name}` is a variable"),
                    "packet offsets must be literals or `const`s so honey can bounds-check the packet once on entry",
                );
                None
            }
            _ => self.const_eval(e),
        }
    }

    /// Evaluate a compile-time constant, reporting (once) if it isn't one.
    fn const_eval(&mut self, e: &Expr) -> Option<i64> {
        match &e.kind {
            ExprKind::Int(n) => Some(*n as i64),
            ExprKind::Ident(name) => {
                if let Some((_, v)) = self.consts.get(name) {
                    return Some(*v as i64);
                }
                if let Some(v) = self.lookup(name) {
                    if let Some(k) = v.konst {
                        return Some(k);
                    }
                    self.error_help(
                        e.span,
                        format!("`{name}` is a runtime value, not a constant"),
                        "loop bounds and indices must be known at compile time so the verifier can prove them bounded; use a literal or a `const`",
                    );
                    return None;
                }
                self.error(e.span, format!("unknown name `{name}`"));
                None
            }
            ExprKind::Binary { op, lhs, rhs } => {
                let a = self.const_eval(lhs)?;
                let b = self.const_eval(rhs)?;
                match op {
                    BinaryOp::Add => Some(a + b),
                    BinaryOp::Sub => Some(a - b),
                    BinaryOp::Mul => Some(a * b),
                    BinaryOp::BitOr => Some(a | b),
                    BinaryOp::BitAnd => Some(a & b),
                    BinaryOp::Shl => Some(a << b),
                    _ => {
                        self.error(e.span, "this operator is not allowed in a constant expression");
                        None
                    }
                }
            }
            _ => {
                self.error_help(e.span, "expected a compile-time constant", "loop bounds and indices must be literals or `const` names");
                None
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StrSide {
    /// A `str<N>` variable with this capacity.
    Local(u32),
    /// A string literal of this byte length.
    Lit(u32),
    No,
}

/// `actual` is acceptable where `expected` is required.
fn compatible(expected: &Ty, actual: &Ty) -> bool {
    match (expected, actual) {
        (a, b) if a == b => true,
        (e, Ty::Int) if e.is_int() => true,
        (Ty::Int, a) if a.is_int() => true,
        // Errors already reported on this operand; don't cascade.
        (_, Ty::Unit) | (Ty::Unit, _) => true,
        _ => false,
    }
}

fn is_call_to(e: &Expr, name: &str) -> bool {
    matches!(&e.kind, ExprKind::Call { callee, .. } if matches!(&callee.kind, ExprKind::Ident(n) if n == name))
}
