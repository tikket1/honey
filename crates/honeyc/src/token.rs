//! The token vocabulary of honey. This file is the *contract* between the
//! lexer (stage 1) and the parser (stage 2): the tests in `tests/lexer.rs`
//! are written against exactly these types.
//!
//! The lexical rules that decide which characters become which token are
//! specified in `docs/LANGUAGE.md`, section "Lexical structure".

/// A half-open byte range `[start, end)` into the source text.
///
/// Byte offsets, not char offsets: `"é"` is one char but two bytes, and the
/// span of that string literal is `0..4` (quote, 2 bytes, quote).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub const fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }
}

/// One lexical token: what it is, and where in the source it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// Every kind of token honey has. Keep this list in sync with
/// `docs/LANGUAGE.md`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TokenKind {
    // ---- literals & names ------------------------------------------------
    /// `foo`, `_x`, `sys_enter_execve`. Never a keyword (see below).
    Ident(String),
    /// `42`, `0xFF`, `0b1010`, `0o755`, `1_000_000`. Always fits in u64.
    Int(u64),
    /// `"..."` with escapes already processed: the payload is the *decoded*
    /// string, so the source `"a\n"` becomes `Str("a\n")` (two chars).
    Str(String),

    // ---- keywords (used in v1) ------------------------------------------
    Probe,
    Map,
    Event,
    Const,
    Let,
    Mut,
    If,
    Else,
    For,
    In,
    Emit,
    Return,
    True,
    False,
    As,

    // ---- keywords (reserved; lexed as keywords so they can never be names)
    Fn,
    Struct,
    Match,
    While, // reserved precisely so the parser can say "no unbounded loops"
    Break,
    Continue,

    // ---- punctuation -----------------------------------------------------
    LParen,     // (
    RParen,     // )
    LBrace,     // {
    RBrace,     // }
    LBracket,   // [
    RBracket,   // ]
    Comma,      // ,
    Semi,       // ;
    Colon,      // :
    ColonColon, // ::
    Dot,        // .
    DotDot,     // ..
    Arrow,      // ->
    Eq,         // =
    EqEq,       // ==
    Bang,       // !
    BangEq,     // !=
    Lt,         // <
    LtEq,       // <=
    Gt,         // >
    GtEq,       // >=
    Plus,       // +
    Minus,      // -
    Star,       // *
    Slash,      // /
    Percent,    // %
    Amp,        // &
    AmpAmp,     // &&
    Pipe,       // |
    PipePipe,   // ||
    Caret,      // ^
    Tilde,      // ~
    Shl,        // <<
    Shr,        // >>

    /// End of input. Always the last token; its span is `len..len`.
    Eof,
}

/// Why lexing failed. `span` points at the offending text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub kind: LexErrorKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexErrorKind {
    /// A character that cannot start any token (`@`, `$`, `é`, ...).
    /// Span covers that one character (which may be more than one byte).
    UnexpectedChar(char),
    /// A `"` with no closing `"` before end of input.
    /// Span runs from the opening quote to end of input.
    UnterminatedString,
    /// A `/*` with no matching `*/` before end of input.
    /// Span runs from the `/*` to end of input.
    UnterminatedComment,
    /// A backslash followed by something that is not a known escape.
    /// Span covers the backslash and the character after it.
    InvalidEscape,
    /// An integer literal whose value does not fit in u64.
    /// Span covers the whole literal.
    IntegerOverflow,
}
