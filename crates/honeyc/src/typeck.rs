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

use crate::addr;
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
    /// A 16-byte IPv6 address (a stack buffer; only from `pkt.ipv6`).
    Ipv6,
    /// A 6-byte MAC address (a stack buffer; only from `pkt.mac`).
    Mac,
    /// The result of `map.get`: maybe a pointer, must be checked.
    Option(Box<Ty>),
    /// The result of `tcp.opt(kind)`: maybe a value, must be checked.
    OptionVal(Box<Ty>),
    /// A checked pointer into a map value.
    Ref(Box<Ty>),
    /// A kernel pointer to a named struct (from `arg(n)` typed `ptr<S>`).
    KPtr(u32, String),
    /// A kernel pointer to a char: a string address for `read_kernel_str`.
    KCharPtr,
    /// A view of packet bytes as a named struct (`let ip: ptr<iphdr> = pkt.at(14)`).
    /// Read with `.field`; lives nowhere at runtime.
    PktPtr(u32, String),
    /// The bytes after a transport header (`let body = tcp.payload();`):
    /// a runtime-length view read with bounded methods.
    PktBytes,
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
            // An IPv4 address is a u32 to the type system; the loader prints it
            // as a dotted quad.
            ("ipv4", []) => Ok(Ty::U32),
            ("ipv6", []) => Ok(Ty::Ipv6),
            ("mac", []) => Ok(Ty::Mac),
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
            Ty::Ipv6 => 16,
            Ty::Mac => 8,
            Ty::PktPtr(..) | Ty::PktBytes | Ty::Unit => 0,
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
            Ty::Ipv6 => write!(f, "ipv6"),
            Ty::Mac => write!(f, "mac"),
            Ty::Option(inner) => write!(f, "Option<&{inner}>"),
            Ty::OptionVal(inner) => write!(f, "Option<{inner}>"),
            Ty::Ref(inner) => write!(f, "&{inner}"),
            Ty::KPtr(_, name) => write!(f, "ptr<{name}>"),
            Ty::KCharPtr => write!(f, "ptr<char>"),
            Ty::PktPtr(_, name) => write!(f, "ptr<{name}> (packet)"),
            Ty::PktBytes => write!(f, "payload (packet)"),
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
    /// A USDT marker (`provider:name`) compiled into a user binary.
    Usdt,
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
    /// Whether this probe has run `pkt.ipv6_l4(...)` (so `pkt.l4()` is bound).
    l4_ready: bool,
    /// The local that currently owns the runtime packet pointer (R9): the
    /// last `pkt.view` / `pkt.l4()` / `.payload()` binding. Binding another
    /// replaces it, and the previous one must not be read again.
    dyn_owner: Option<String>,
    dead_views: Vec<(String, String)>,
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
        l4_ready: false,
        dyn_owner: None,
        dead_views: Vec::new(),
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

    /// `name` takes over the runtime packet pointer; whoever had it is dead.
    fn take_dyn(&mut self, name: &str) {
        if let Some(prev) = self.dyn_owner.replace(name.to_string())
            && prev != name
        {
            self.dead_views.push((prev, name.to_string()));
        }
    }

    /// Reading a replaced runtime view would read through the new one's
    /// pointer: a silent wrong answer, so it is an error.
    fn check_live(&mut self, name: &str, span: Span) {
        if let Some((_, by)) = self.dead_views.iter().find(|(n, _)| n == name).cloned() {
            self.error_help(
                span,
                format!("`{name}` is no longer a valid view: `{by}` took the packet pointer"),
                "one runtime view is live at a time; read everything you need from a view before binding the next",
            );
        }
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
                Ok(ty) if ty.is_int() || ty == Ty::Bool || matches!(ty, Ty::Str(_) | Ty::Ipv6 | Ty::Mac) => {
                    if fields.iter().any(|(n, _)| n == &f.name.name) {
                        self.error(f.name.span, format!("duplicate field `{}`", f.name.name));
                    }
                    fields.push((f.name.name.clone(), ty));
                }
                Ok(ty) => self.error(f.ty.span, format!("event fields must be integers, bool, str<N>, ipv4, ipv6 or mac, not `{ty}`")),
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
            ("usdt", 1) => Some(ProbeKind::Usdt),
            ("usdt", _) => {
                self.error(p.span, "`usdt` takes one string argument: `\"/path/to/binary:provider:name\"`");
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
                    "use `tracepoint`, `kprobe`, `kretprobe`, `lsm`, `xdp`, `uprobe`, `uretprobe`, or `usdt`",
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
        if kind == Some(ProbeKind::Usdt)
            && let [target] = p.args.as_slice()
            && target.matches(':').count() < 2
        {
            self.error_help(
                p.span,
                "usdt target must be `path:provider:name`",
                "for example `usdt(\"/usr/bin/python3:python:function__entry\")`",
            );
        }
        self.probe_kind = kind;
        self.l4_ready = false;
        self.dyn_owner = None;
        self.dead_views.clear();
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
                        // What `Some(x)` binds: a checked pointer for a map
                        // lookup, the value itself for a TCP option.
                        let bound = match t {
                            Ty::Option(inner) => Some(Ty::Ref(inner)),
                            Ty::OptionVal(inner) => Some(*inner),
                            other => {
                                self.error_help(
                                    value.span,
                                    format!("`if let` needs an `Option` from `map.get` or `tcp.opt`, found `{other}`"),
                                    "only map lookups and TCP option walks can be `None`",
                                );
                                None
                            }
                        };
                        if let Some(bound) = bound {
                            match (pattern.name.name.as_str(), &pattern.binding) {
                                ("Some", Some(b)) => {
                                    // The binding exists only inside this block.
                                    self.declare(&b.name, bound, false, None);
                                }
                                ("None", None) => {}
                                ("Some", None) => self.error(pattern.span, "`Some` needs a binding: `Some(name)`"),
                                ("None", Some(_)) => self.error(pattern.span, "`None` takes no binding"),
                                (other, _) => self.error(pattern.span, format!("unknown pattern `{other}`; use `Some(x)` or `None`")),
                            }
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
        // `let s: str<N> = body.str();` copies from the packet the same way.
        if let ExprKind::MethodCall { receiver, method, args } = &value.kind
            && method.name == "str"
            && let ExprKind::Ident(r) = &receiver.kind
            && matches!(self.lookup(r), Some(Var { ty: Ty::PktBytes, .. }))
        {
            self.check_live(r, receiver.span);
            if !args.is_empty() {
                self.error(value.span, "`.str()` takes no arguments; the `str<N>` annotation is the bound");
            }
            let declared = ty.map(Ty::from_ast);
            match declared {
                Some(Ok(t @ Ty::Str(_))) => self.declare(&name.name, t, mutable, None),
                Some(Ok(other)) => {
                    self.error(ty.unwrap().span, format!("`.str()` produces a `str<N>`, not `{other}`"));
                    self.declare(&name.name, Ty::Unit, mutable, None);
                }
                Some(Err(m)) => {
                    self.error(ty.unwrap().span, m);
                    self.declare(&name.name, Ty::Unit, mutable, None);
                }
                None => {
                    self.error_help(
                        value.span,
                        "`.str()` needs a bounded destination",
                        format!("write `let {}: str<N> = {r}.str();` so the copy has a known length", name.name),
                    );
                    self.declare(&name.name, Ty::Unit, mutable, None);
                }
            }
            return;
        }
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
                        matches!(pt, Ty::KCharPtr | Ty::KPtr(..)) || pt == Ty::U64 || pt == Ty::Int
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
            && is_pkt_at(value)
        {
            // A packet view: only in xdp, struct from BTF, bounded like every
            // other packet read (offset + sizeof(struct) within the limit).
            if self.probe_kind != Some(ProbeKind::Xdp) {
                self.error(value.span, "`pkt.at` is only available in an `xdp` probe");
            }
            let target = self.ptr_target(t);
            let ExprKind::MethodCall { method, args, .. } = &value.kind else { unreachable!() };
            match (method.name.as_str(), args.as_slice()) {
                ("at", [off]) => {
                    if let Some((_, sname)) = &target {
                        let size = self.btf.and_then(|b| b.struct_size(sname)).unwrap_or(0);
                        match self.const_eval_global(off) {
                            Some(o) if o < 0 => self.error(off.span, "packet offset must not be negative"),
                            Some(o) if o as u32 + size > MAX_PKT_BOUND => self.error_help(
                                off.span,
                                format!("`{sname}` ({size} bytes) at offset {o} ends past {MAX_PKT_BOUND} bytes, the most an XDP probe may inspect"),
                                "keep the view within the first 256 bytes of the packet",
                            ),
                            _ => {}
                        }
                    }
                }
                ("at", _) => self.error(value.span, "`pkt.at` takes one constant offset"),
                ("view", [off]) => {
                    // a runtime offset: bounds-checked when bound, not here
                    let ot = self.expr(off);
                    if !ot.is_int() && ot != Ty::Unit {
                        self.error(off.span, format!("`pkt.view` takes an integer offset, found `{ot}`"));
                    }
                }
                ("view", _) => self.error(value.span, "`pkt.view` takes one offset expression"),
                ("l4", []) => {
                    if !self.l4_ready {
                        self.error_help(
                            value.span,
                            "`pkt.l4()` needs a preceding `pkt.ipv6_l4(...)` in this probe",
                            "walk the IPv6 extension headers first: `let proto = pkt.ipv6_l4(14);`",
                        );
                    }
                }
                ("l4", _) => self.error(value.span, "`pkt.l4()` takes no arguments"),
                _ => unreachable!(),
            }
            if method.name != "at" {
                self.take_dyn(&name.name);
            }
            match target {
                Some((id, sname)) => self.declare(&name.name, Ty::PktPtr(id, sname), mutable, None),
                None => self.declare(&name.name, Ty::Unit, mutable, None),
            }
            return;
        }
        if let Some(t) = ty
            && t.name.name == "ptr"
        {
            let target = self.ptr_target(t);
            let at = self.expr(value);
            if at != Ty::U64 && at != Ty::Int && !matches!(at, Ty::KPtr(..) | Ty::KCharPtr) {
                self.error(value.span, format!("`ptr<...>` must come from an argument or another pointer, found `{at}`"));
            }
            match target {
                Some((id, sname)) => self.declare(&name.name, Ty::KPtr(id, sname), mutable, None),
                None => self.declare(&name.name, Ty::Unit, mutable, None),
            }
            return;
        }

        let before = self.diags.len();
        let actual = self.expr(value);
        let value_had_errors = self.diags.len() > before;
        if actual == Ty::PktBytes {
            if let Some(t) = ty {
                self.error(t.span, "a payload view takes no type annotation");
            }
            self.take_dyn(&name.name);
        }
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
        if matches!(ty, Ty::Ipv6 | Ty::Mac) && !is_pkt_call(value) && !matches!(value.kind, ExprKind::Field { .. }) {
            self.error_help(value.span, format!("an `{ty}` value can only come straight from the packet"), format!("write `let x: {ty} = pkt.{ty}(offset);`"));
        }
        self.declare(&name.name, ty, mutable, None);
    }

    fn assign(&mut self, target: &Expr, value: &Expr) {
        match &target.kind {
            ExprKind::Ident(n) => {
                let Some(var) = self.lookup(n).cloned() else {
                    return self.error(target.span, format!("unknown variable `{n}`"));
                };
                if matches!(var.ty, Ty::Ipv6 | Ty::Mac | Ty::Str(_)) {
                    self.error(target.span, format!("`{n}` is a `{}` buffer and cannot be reassigned", var.ty));
                    self.expr(value);
                    return;
                }
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
            // `view.field = value`: a packet write through a bounded view.
            ExprKind::Field { expr: view, field } => {
                let base = self.expr(view);
                let Ty::PktPtr(sid, sname) = base else {
                    if base != Ty::Unit {
                        self.error_help(
                            target.span,
                            format!("cannot assign to a field of `{base}`"),
                            "only packet views (`ptr<Struct>` from `pkt.at`/`pkt.view`) can be written through",
                        );
                    }
                    self.expr(value);
                    return;
                };
                let ft = self.pkt_field_type(sid, &sname, field);
                if let Some(btf) = self.btf
                    && let Some(m) = btf.member_of(sid, &field.name)
                    && m.bitfield()
                {
                    self.error_help(field.span, format!("cannot write the bitfield `{}`", field.name), "honey writes whole fields only");
                    self.expr(value);
                    return;
                }
                match ft {
                    // Byte blobs come from the packet, a blob local, or a literal.
                    Ty::Mac | Ty::Ipv6 => match &value.kind {
                        ExprKind::Str(lit) => {
                            let ok = if ft == Ty::Mac { addr::parse_mac(lit).is_some() } else { addr::parse_ipv6(lit).is_some() };
                            if !ok {
                                self.error(value.span, format!("{lit:?} is not a `{ft}` literal"));
                            }
                        }
                        ExprKind::Field { .. } | ExprKind::Ident(_) => {
                            let vt = self.expr(value);
                            self.expect(&ft, &vt, value.span);
                        }
                        _ => self.error_help(
                            value.span,
                            format!("a `{ft}` can only be written from the packet, a `{ft}` local, or a literal"),
                            format!("e.g. `eth.h_dest = eth.h_source;` or `eth.h_dest = \"{}\";`", if ft == Ty::Mac { "aa:bb:cc:dd:ee:ff" } else { "fe80::1" }),
                        ),
                    },
                    Ty::PktPtr(..) => {
                        self.error_help(target.span, format!("cannot assign the embedded struct `{}`", field.name), "write its fields one by one");
                        self.expr(value);
                    }
                    Ty::Unit => {
                        self.expr(value);
                    }
                    _ => {
                        let vt = self.expr(value);
                        self.expect(&ft, &vt, value.span);
                        self.literal_fits(&ft, value);
                    }
                }
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
    fn ptr_target(&mut self, t: &Type) -> Option<(u32, String)> {
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
        let Some(id) = btf.struct_id(&name) else {
            self.error(t.span, format!("`{name}` is not a kernel struct in the provided BTF"));
            return None;
        };
        Some((id, name))
    }

    /// How an embedded struct is named in messages: its own name, or the
    /// path to it when it is anonymous (`icmphdr.un`).
    fn embedded_name(parent: &str, own: &str, field: &str) -> String {
        if own.is_empty() { format!("{parent}.{field}") } else { own.to_string() }
    }

    /// Type of `base.field` where `base` is a kernel struct pointer.
    fn field_type(&mut self, id: u32, struct_name: &str, field: &Ident) -> Ty {
        let Some(btf) = self.btf else {
            self.error(field.span, "kernel field access needs `--btf`");
            return Ty::Unit;
        };
        let Some(member) = btf.member_of(id, &field.name) else {
            self.error(field.span, format!("`struct {struct_name}` has no field `{}`", field.name));
            return Ty::Unit;
        };
        if member.bitfield() {
            return match member.bit_size {
                0..=8 => Ty::U8,
                9..=16 => Ty::U16,
                17..=32 => Ty::U32,
                _ => Ty::U64,
            };
        }
        match btf.resolve(member.type_id) {
            Resolved::Int { bytes, .. } => match bytes {
                1 => Ty::U8,
                2 => Ty::U16,
                4 => Ty::U32,
                _ => Ty::U64,
            },
            // A char array (task_struct.comm): its address, readable with read_kernel_str.
            Resolved::Array { elem_bytes: 1, .. } => Ty::KCharPtr,
            Resolved::Array { .. } => {
                self.error(field.span, format!("field `{}` is an array honey can't read as a value; only byte arrays are supported", field.name));
                Ty::Unit
            }
            Resolved::Struct { id, name } => Ty::KPtr(id, Self::embedded_name(struct_name, &name, &field.name)),
            Resolved::PtrToStruct { id, name } => Ty::KPtr(id, name),
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

    /// Type of `view.field` where `view` is a packet struct view.
    fn pkt_field_type(&mut self, id: u32, struct_name: &str, field: &Ident) -> Ty {
        let Some(btf) = self.btf else {
            self.error(field.span, "packet struct access needs `--btf`");
            return Ty::Unit;
        };
        let Some(member) = btf.member_of(id, &field.name) else {
            self.error(field.span, format!("`struct {struct_name}` has no field `{}`", field.name));
            return Ty::Unit;
        };
        if member.bitfield() {
            return match member.bit_size {
                0..=8 => Ty::U8,
                9..=16 => Ty::U16,
                17..=32 => Ty::U32,
                _ => Ty::U64,
            };
        }
        match btf.resolve(member.type_id) {
            Resolved::Int { bytes, .. } => match bytes {
                1 => Ty::U8,
                2 => Ty::U16,
                4 => Ty::U32,
                _ => Ty::U64,
            },
            Resolved::Array { elem_bytes: 1, len: 6 } => Ty::Mac,
            Resolved::Array { elem_bytes: 1, len: 16 } => Ty::Ipv6,
            Resolved::Struct { name, .. } if name == "in6_addr" => Ty::Ipv6,
            Resolved::Struct { id, name } => Ty::PktPtr(id, Self::embedded_name(struct_name, &name, &field.name)),
            Resolved::PtrToStruct { .. } | Resolved::PtrToChar | Resolved::PtrToOther => {
                self.error(field.span, format!("`{}` is a pointer; packet structs are read by value, not followed", field.name));
                Ty::Unit
            }
            Resolved::Array { .. } | Resolved::Other => {
                self.error(field.span, format!("field `{}` has a type honey can't read from a packet", field.name));
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
                    let t = v.ty.clone();
                    if matches!(t, Ty::PktPtr(..) | Ty::PktBytes) {
                        self.check_live(name, e.span);
                    }
                    return t;
                }
                // (a PktPtr local is fine to name: `.field` follows.)
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
                    Ty::KPtr(id, name) => self.field_type(id, &name, field),
                    Ty::PktPtr(id, name) => self.pkt_field_type(id, &name, field),
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
            ExprKind::Str(lit) => StrSide::Lit(lit.clone()),
            ExprKind::Ident(n) => match self.lookup(n).map(|v| v.ty.clone()) {
                Some(Ty::Str(cap)) => StrSide::Local(cap),
                Some(t @ (Ty::Ipv6 | Ty::Mac)) => StrSide::Blob(t),
                _ => StrSide::No,
            },
            _ => StrSide::No,
        }
    }

    fn binary(&mut self, op: BinaryOp, lhs: &Expr, rhs: &Expr, span: Span) -> Ty {
        // String and address comparisons: `s == "lit"`, `s != t`,
        // `a == "::1"`, `m == other_mac`, `ip == "10.0.0.1"`. Only `==` / `!=`.
        let (ls, rs) = (self.str_side(lhs), self.str_side(rhs));
        if ls != StrSide::No || rs != StrSide::No {
            if !matches!(op, BinaryOp::Eq | BinaryOp::Ne) {
                self.error_help(span, format!("strings and addresses do not support `{}`", op.symbol()), "they can only be compared with `==` and `!=`");
                return Ty::Bool;
            }
            let lhs_plain = ls == StrSide::No;
            match (ls, rs) {
                (StrSide::Lit(_), StrSide::Lit(_)) => {
                    self.error(span, "comparing two string literals; compare a variable with a literal");
                }
                (StrSide::Local(cap), StrSide::Lit(lit)) | (StrSide::Lit(lit), StrSide::Local(cap)) => {
                    let len = lit.len() as u32;
                    if len > cap {
                        self.error_help(
                            span,
                            format!("this literal is {len} bytes but the string is only `str<{cap}>`; they can never be equal"),
                            "enlarge the `str<N>` or shorten the literal",
                        );
                    }
                }
                (StrSide::Local(_), StrSide::Local(_)) => {}
                (StrSide::Blob(a), StrSide::Blob(b)) => {
                    if a != b {
                        self.error(span, format!("cannot compare `{a}` with `{b}`"));
                    }
                }
                (StrSide::Blob(t), StrSide::Lit(lit)) | (StrSide::Lit(lit), StrSide::Blob(t)) => {
                    let ok = match t {
                        Ty::Ipv6 => addr::parse_ipv6(&lit).is_some(),
                        _ => addr::parse_mac(&lit).is_some(),
                    };
                    if !ok {
                        let example = if t == Ty::Ipv6 { "\"2001:db8::1\"" } else { "\"aa:bb:cc:dd:ee:ff\"" };
                        self.error_help(span, format!("{lit:?} is not a valid `{t}` literal"), format!("write it like {example}"));
                    }
                }
                (StrSide::Blob(t), StrSide::Local(_)) | (StrSide::Local(_), StrSide::Blob(t)) => {
                    self.error(span, format!("cannot compare `{t}` with a `str<N>`"));
                }
                (StrSide::Local(cap), StrSide::No) | (StrSide::No, StrSide::Local(cap)) => {
                    let other = if lhs_plain { self.expr(lhs) } else { self.expr(rhs) };
                    if other != Ty::Unit {
                        self.error(span, format!("cannot compare `str<{cap}>` with `{other}`"));
                    }
                }
                (StrSide::Blob(t), StrSide::No) | (StrSide::No, StrSide::Blob(t)) => {
                    let other = if lhs_plain { self.expr(lhs) } else { self.expr(rhs) };
                    if other != Ty::Unit {
                        self.error(span, format!("cannot compare `{t}` with `{other}`"));
                    }
                }
                (StrSide::Lit(lit), StrSide::No) | (StrSide::No, StrSide::Lit(lit)) => {
                    // A dotted quad against a u32 address is fine.
                    let other = if lhs_plain { self.expr(lhs) } else { self.expr(rhs) };
                    let is_u32 = other == Ty::U32 || other == Ty::Int;
                    if other != Ty::Unit && !(is_u32 && addr::parse_ipv4(&lit).is_some()) {
                        if is_u32 {
                            self.error_help(span, format!("{lit:?} is not an IPv4 address literal"), "compare a `u32` address with a dotted quad like \"10.0.0.1\"");
                        } else {
                            self.error_help(span, format!("cannot compare a string literal with `{other}`"), "only a `str<N>`, `ipv6`, `mac`, or `u32` address can be compared with a literal");
                        }
                    }
                }
                (StrSide::No, StrSide::No) => unreachable!(),
            }
            return Ty::Bool;
        }

        let l = self.expr(lhs);
        let r = self.expr(rhs);
        if matches!(l, Ty::Ipv6 | Ty::Mac) || matches!(r, Ty::Ipv6 | Ty::Mac) {
            self.error(span, "`ipv6` and `mac` values can only be compared with `==` and `!=` against another address or a literal");
            return Ty::Bool;
        }
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
            ("in_subnet", [a, cidr]) => {
                let at = self.expr(a);
                let ExprKind::Str(lit) = &cidr.kind else {
                    self.error(cidr.span, "`in_subnet` takes a CIDR string literal like \"10.0.0.0/8\"");
                    return Ty::Bool;
                };
                match at {
                    Ty::U32 | Ty::Int => {
                        if addr::parse_cidr4(lit).is_none() {
                            self.error_help(cidr.span, format!("{lit:?} is not an IPv4 CIDR"), "write it like \"10.0.0.0/8\"");
                        }
                    }
                    Ty::Ipv6 => {
                        if addr::parse_cidr6(lit).is_none() {
                            self.error_help(cidr.span, format!("{lit:?} is not an IPv6 CIDR"), "write it like \"fe80::/10\"");
                        }
                    }
                    Ty::Unit => {}
                    other => self.error(a.span, format!("`in_subnet` needs a `u32` or `ipv6` address, found `{other}`")),
                }
                Ty::Bool
            }
            ("in_subnet", _) => {
                self.error(span, "`in_subnet(address, \"cidr\")` takes an address and a CIDR literal");
                Ty::Bool
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
            ("csum_update", [c, old, new]) => {
                // RFC 1624 incremental update: all three are 16-bit words in
                // the same byte order as the header fields honey reads.
                for a in [c, old, new] {
                    let t = self.expr(a);
                    if !t.is_int() && t != Ty::Unit {
                        self.error(a.span, format!("`csum_update` takes integers, found `{t}`"));
                    }
                }
                Ty::U16
            }
            ("csum_update", _) => {
                self.error_help(span, "`csum_update` takes three arguments", "`csum_update(old_csum, old_word, new_word)`");
                for a in args {
                    self.expr(a);
                }
                Ty::Unit
            }
            ("redirect", [iface]) => {
                if self.probe_kind != Some(ProbeKind::Xdp) {
                    self.error_help(span, "`redirect()` is only available in an `xdp` probe", "only an XDP program holds a packet to send elsewhere");
                }
                match &iface.kind {
                    ExprKind::Str(n) if !n.is_empty() && n.len() < 16 => {}
                    ExprKind::Str(_) => self.error(iface.span, "an interface name is 1..15 characters"),
                    _ => self.error_help(iface.span, "`redirect` takes an interface name literal", "e.g. `redirect(\"eth1\")`; the loader resolves it to an ifindex"),
                }
                Ty::Unit
            }
            ("redirect", _) => {
                self.error(span, "`redirect(\"iface\")` takes one interface name");
                Ty::Unit
            }
            ("drop" | "pass" | "tx", []) => {
                if self.probe_kind != Some(ProbeKind::Xdp) {
                    self.error_help(
                        span,
                        format!("`{name}()` is only available in an `xdp` probe"),
                        "only an XDP program decides a packet's fate; use `probe xdp(\"iface\") {{ ... }}`",
                    );
                }
                Ty::Unit
            }
            ("drop" | "pass" | "tx", _) => {
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
                ("at" | "view" | "l4", _) => {
                    self.error_help(span, format!("`pkt.{}` needs a struct type", method.name), "bind it: `let ip: ptr<iphdr> = pkt.at(14);` then read `ip.saddr`");
                    Ty::Unit
                }
                ("ipv6_l4", [off]) => {
                    // walks the extension-header chain from the IPv6 header at `off`
                    match self.const_eval_global(off) {
                        Some(o) if o < 0 => self.error(off.span, "packet offset must not be negative"),
                        Some(o) if o as u32 + 40 > MAX_PKT_BOUND => self.error(off.span, "the IPv6 header must lie within the first 256 bytes"),
                        _ => {}
                    }
                    self.l4_ready = true;
                    Ty::U8
                }
                ("ipv6_l4", _) => {
                    self.error(span, "`pkt.ipv6_l4(offset)` takes the constant offset of the IPv6 header (14 after Ethernet)");
                    Ty::U8
                }
                ("u8" | "u16" | "u32" | "ipv6" | "mac", [off]) => {
                    let width: u32 = match method.name.as_str() {
                        "u8" => 1,
                        "u16" => 2,
                        "u32" => 4,
                        "mac" => 6,
                        _ => 16,
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
                        4 => Ty::U32,
                        6 => Ty::Mac,
                        _ => Ty::Ipv6,
                    }
                }
                ("u8" | "u16" | "u32" | "ipv6" | "mac", _) => {
                    self.error(span, format!("`pkt.{}` takes one constant offset", method.name));
                    Ty::Unit
                }
                (m, _) => {
                    self.error(method.span, format!("`pkt` has no method `{m}`; use `u8/u16/u32(off)`, `ipv6(off)`, `mac(off)`, `at(off)`, `view(expr)`, `ipv6_l4(off)`, `l4()`, or `len()`"));
                    Ty::Unit
                }
            };
        }

        // The payload view: `body.len()`, `body.u8(i)`, `body.starts_with("..")`.
        if let Some(Var { ty: Ty::PktBytes, .. }) = self.lookup(rname) {
            self.check_live(rname, receiver.span);
            return match (method.name.as_str(), args) {
                ("len", []) => Ty::U32,
                ("u8" | "u16" | "u32", [off]) => {
                    let width: u32 = match method.name.as_str() {
                        "u8" => 1,
                        "u16" => 2,
                        _ => 4,
                    };
                    match self.const_eval(off) {
                        Some(o) if o < 0 => self.error(off.span, "payload offset must not be negative"),
                        Some(o) if o as u32 + width > MAX_PKT_BOUND => self.error(off.span, format!("payload read at offset {o} ends past {MAX_PKT_BOUND} bytes")),
                        _ => {}
                    }
                    match width {
                        1 => Ty::U8,
                        2 => Ty::U16,
                        _ => Ty::U32,
                    }
                }
                ("u8" | "u16" | "u32", _) => {
                    self.error(span, format!("`.{}` takes one constant offset into the payload", method.name));
                    Ty::Unit
                }
                ("starts_with", [arg]) => {
                    match &arg.kind {
                        ExprKind::Str(lit) if lit.is_empty() => self.error(arg.span, "an empty prefix matches everything"),
                        ExprKind::Str(lit) if lit.len() as u32 > MAX_PKT_BOUND => self.error(arg.span, format!("prefix longer than {MAX_PKT_BOUND} bytes")),
                        ExprKind::Str(_) => {}
                        _ => self.error(arg.span, "`starts_with` takes a string literal"),
                    }
                    Ty::Bool
                }
                ("starts_with", _) => {
                    self.error(span, "`starts_with` takes one string literal");
                    Ty::Unit
                }
                ("contains", [lit, window]) => {
                    // a search needs a bound the verifier can see: the window
                    let n = match &lit.kind {
                        ExprKind::Str(l) if l.is_empty() => {
                            self.error(lit.span, "an empty needle matches everything");
                            0
                        }
                        ExprKind::Str(l) => l.len() as i64,
                        _ => {
                            self.error(lit.span, "`contains` takes a string literal to look for");
                            0
                        }
                    };
                    match self.const_eval(window) {
                        Some(w) if w < 1 || w > MAX_PKT_BOUND as i64 => self.error(window.span, format!("the search window must be 1..={MAX_PKT_BOUND} bytes")),
                        Some(w) if n > w => self.error(window.span, format!("the needle is {n} bytes but the window only {w}")),
                        _ => {}
                    }
                    Ty::Bool
                }
                ("contains", _) => {
                    self.error_help(span, "`contains` takes a literal and a window", "`body.contains(\"Failed password\", 96)` searches the first 96 bytes; the window is the bound the verifier needs");
                    Ty::Unit
                }
                ("str", _) => {
                    self.error_help(span, "`.str()` must initialise a bounded string", format!("write `let s: str<N> = {rname}.str();`"));
                    Ty::Unit
                }
                (m, _) => {
                    self.error_help(method.span, format!("payload has no method `{m}`"), "use `len()`, `u8/u16/u32(off)`, `starts_with(\"...\")`, `contains(\"...\", window)`, or `let s: str<N> = body.str();`");
                    for a in args {
                        self.expr(a);
                    }
                    Ty::Unit
                }
            };
        }

        // Packet views: `tcp.opt(kind)`, `ip.fix_csum()`, `tcp.payload()`.
        if let Some(Var { ty: Ty::PktPtr(_, sname), .. }) = self.lookup(rname).cloned() {
            self.check_live(rname, receiver.span);
            return match (method.name.as_str(), args) {
                ("payload", []) => {
                    if sname != "tcphdr" && sname != "udphdr" {
                        self.error_help(
                            span,
                            format!("`.payload()` follows a TCP or UDP header, but `{rname}` is a `ptr<{sname}>`"),
                            "bind the transport header first: `let tcp: ptr<tcphdr> = pkt.view(14 + ip.ihl * 4);`",
                        );
                    }
                    Ty::PktBytes
                }
                ("payload", _) => {
                    self.error(span, "`.payload()` takes no arguments");
                    Ty::Unit
                }
                ("opt", [kind]) => {
                    if sname != "tcphdr" {
                        self.error_help(
                            span,
                            format!("`.opt(kind)` walks TCP options, but `{rname}` is a `ptr<{sname}>`"),
                            "bind the TCP header first: `let tcp: ptr<tcphdr> = pkt.view(14 + ip.ihl * 4);`",
                        );
                    }
                    if let Some(k) = self.const_eval(kind)
                        && !(0..=255).contains(&k)
                    {
                        self.error(kind.span, "a TCP option kind is one byte (0..=255)");
                    }
                    Ty::OptionVal(Box::new(Ty::U32))
                }
                ("opt", _) => {
                    self.error_help(span, "`.opt(kind)` takes one constant option kind", "e.g. `tcp.opt(2)` for MSS, `tcp.opt(3)` for window scale");
                    Ty::Unit
                }
                ("fix_csum", []) => {
                    if sname != "iphdr" {
                        self.error_help(
                            span,
                            format!("`.fix_csum()` recomputes an IPv4 header checksum, but `{rname}` is a `ptr<{sname}>`"),
                            "call it on the `ptr<iphdr>` view you wrote to",
                        );
                    }
                    Ty::Unit
                }
                ("fix_csum", _) => {
                    self.error(span, "`.fix_csum()` takes no arguments");
                    Ty::Unit
                }
                (m, _) => {
                    self.error_help(method.span, format!("packet view has no method `{m}`"), "views have `opt(kind)` and `payload()` on a `ptr<tcphdr>`, `payload()` on a `ptr<udphdr>`, and `fix_csum()` on a `ptr<iphdr>`");
                    for a in args {
                        self.expr(a);
                    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum StrSide {
    /// A `str<N>` variable with this capacity.
    Local(u32),
    /// A string literal (its text).
    Lit(String),
    /// An `ipv6` or `mac` variable.
    Blob(Ty),
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

/// `pkt.at(off)`, `pkt.view(expr)`, `pkt.l4()`: expressions that bind a
/// packet struct view (and therefore need a `ptr<S>` annotation).
fn is_pkt_at(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::MethodCall { receiver, method, .. }
        if matches!(&receiver.kind, ExprKind::Ident(n) if n == "pkt")
            && matches!(method.name.as_str(), "at" | "view" | "l4"))
}

/// `pkt.ipv6(...)` / `pkt.mac(...)`: the only producers of blob values.
fn is_pkt_call(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::MethodCall { receiver, method, .. }
        if matches!(&receiver.kind, ExprKind::Ident(n) if n == "pkt") && (method.name == "ipv6" || method.name == "mac"))
}

fn is_call_to(e: &Expr, name: &str) -> bool {
    matches!(&e.kind, ExprKind::Call { callee, .. } if matches!(&callee.kind, ExprKind::Ident(n) if n == name))
}
