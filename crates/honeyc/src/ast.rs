//! The abstract syntax tree: what a honey program *means*, structurally,
//! with the punctuation gone. Produced by the parser (stage 2), consumed by
//! the type checker (stage 4) and the code generator (stage 3).
//!
//! Every node keeps the `Span` of the source text it came from, so later
//! stages can report errors at the right place.
//!
//! The shapes here follow `docs/LANGUAGE.md` § 4 one production at a time.

use crate::token::Span;

/// A whole `.hny` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub items: Vec<Item>,
}

/// A name, with where it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

// ------------------------------------------------------------------ items

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Const(ConstDecl),
    Map(MapDecl),
    Event(EventDecl),
    Probe(ProbeDecl),
}

impl Item {
    pub fn span(&self) -> Span {
        match self {
            Item::Const(c) => c.span,
            Item::Map(m) => m.span,
            Item::Event(e) => e.span,
            Item::Probe(p) => p.span,
        }
    }
}

/// `const NAME: type = expr;`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstDecl {
    pub name: Ident,
    pub ty: Type,
    pub value: Expr,
    pub span: Span,
}

/// `map NAME: kind<args>[capacity];`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapDecl {
    pub name: Ident,
    /// `hash`, `array`, ... The parser doesn't validate this; the type
    /// checker does.
    pub kind: Ident,
    pub args: Vec<Type>,
    pub capacity: u64,
    pub span: Span,
}

/// `event NAME { field: type, ... }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDecl {
    pub name: Ident,
    pub fields: Vec<Field>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: Ident,
    pub ty: Type,
    pub span: Span,
}

/// `probe kind("arg", "arg") { ... }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeDecl {
    /// `tracepoint`, `kprobe`, ... Validated by the type checker.
    pub kind: Ident,
    pub args: Vec<String>,
    pub body: Block,
    pub span: Span,
}

// ------------------------------------------------------------------ types

/// `u32`, `str<16>`, `hash<u32, u64>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Type {
    pub name: Ident,
    pub args: Vec<TypeArg>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeArg {
    Type(Type),
    /// The `16` in `str<16>`.
    Int(u64),
}

// ------------------------------------------------------------- statements

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StmtKind {
    /// `let [mut] name [: type] = value;`
    Let {
        mutable: bool,
        name: Ident,
        ty: Option<Type>,
        value: Expr,
    },
    /// `target = value;` where `target` is a name or `*name`.
    Assign { target: Expr, value: Expr },
    /// `if cond { } [else { }]`. An `else if` is represented as an `else`
    /// block containing a single `If` statement.
    If {
        cond: Cond,
        then: Block,
        otherwise: Option<Block>,
    },
    /// `for var in start..end { }`
    For {
        var: Ident,
        start: Expr,
        end: Expr,
        body: Block,
    },
    /// `emit Event { field: value, ... };`
    Emit {
        event: Ident,
        fields: Vec<(Ident, Expr)>,
    },
    /// `return [value];`
    Return(Option<Expr>),
    /// `expr;`
    Expr(Expr),
}

/// The condition of an `if`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    Expr(Expr),
    /// `if let pattern = value`
    Let { pattern: Pattern, value: Expr },
}

/// `Some(x)` or `None`. Only used in `if let`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub name: Ident,
    pub binding: Option<Ident>,
    pub span: Span,
}

// ------------------------------------------------------------ expressions

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprKind {
    Int(u64),
    Str(String),
    Bool(bool),
    Ident(String),
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// `expr as type`
    Cast {
        expr: Box<Expr>,
        ty: Type,
    },
    /// `callee(args)`
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
    /// `receiver.method(args)`
    MethodCall {
        receiver: Box<Expr>,
        method: Ident,
        args: Vec<Expr>,
    },
    /// `expr.field`
    Field {
        expr: Box<Expr>,
        field: Ident,
    },
    /// `expr[index]`
    Index {
        expr: Box<Expr>,
        index: Box<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,   // !
    Neg,   // -
    BitNot, // ~
    Deref, // *
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Or,  // ||
    And, // &&
    Eq,  // ==
    Ne,  // !=
    Lt,  // <
    Le,  // <=
    Gt,  // >
    Ge,  // >=
    BitOr,  // |
    BitXor, // ^
    BitAnd, // &
    Shl, // <<
    Shr, // >>
    Add, // +
    Sub, // -
    Mul, // *
    Div, // /
    Rem, // %
}

impl UnaryOp {
    pub fn symbol(self) -> &'static str {
        match self {
            UnaryOp::Not => "!",
            UnaryOp::Neg => "-",
            UnaryOp::BitNot => "~",
            UnaryOp::Deref => "*",
        }
    }
}

impl BinaryOp {
    pub fn symbol(self) -> &'static str {
        match self {
            BinaryOp::Or => "||",
            BinaryOp::And => "&&",
            BinaryOp::Eq => "==",
            BinaryOp::Ne => "!=",
            BinaryOp::Lt => "<",
            BinaryOp::Le => "<=",
            BinaryOp::Gt => ">",
            BinaryOp::Ge => ">=",
            BinaryOp::BitOr => "|",
            BinaryOp::BitXor => "^",
            BinaryOp::BitAnd => "&",
            BinaryOp::Shl => "<<",
            BinaryOp::Shr => ">>",
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::Mul => "*",
            BinaryOp::Div => "/",
            BinaryOp::Rem => "%",
        }
    }
}
