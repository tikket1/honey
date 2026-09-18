//! Stage 2: turn tokens into an AST.
//!
//! A hand-written recursive-descent parser: one function per grammar rule in
//! `docs/LANGUAGE.md` § 4, plus precedence climbing for binary expressions.
//! It looks at most one token ahead and never backtracks.
//!
//! The one piece of cleverness is `expect_gt`: the lexer emits `>>` as a
//! single `Shr` token, so when a type like `hash<u32, str<16>>` is being
//! closed the parser splits that token into two `>`s (see LANGUAGE.md § 3.6).

use crate::ast::*;
use crate::lexer;
use crate::token::{LexError, Span, Token, TokenKind};

/// Anything that can go wrong turning text into an AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Lex(LexError),
    Parse(ParseError),
}

impl Error {
    pub fn span(&self) -> Span {
        match self {
            Error::Lex(e) => e.span,
            Error::Parse(e) => e.span,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Error::Lex(e) => format!("{:?}", e.kind),
            Error::Parse(e) => e.message.clone(),
        }
    }
}

impl From<LexError> for Error {
    fn from(e: LexError) -> Self {
        Error::Lex(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::Parse(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

/// Lex and parse a whole program.
pub fn parse(src: &str) -> Result<Program, Error> {
    let tokens = lexer::lex(src)?;
    let mut p = Parser { tokens, pos: 0 };
    let program = p.program()?;
    Ok(program)
}

/// Lex and parse a single expression. Mostly for tests.
pub fn parse_expr(src: &str) -> Result<Expr, Error> {
    let tokens = lexer::lex(src)?;
    let mut p = Parser { tokens, pos: 0 };
    let e = p.expr()?;
    p.expect(TokenKind::Eof, "end of input")?;
    Ok(e)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

type PResult<T> = Result<T, ParseError>;

impl Parser {
    // ------------------------------------------------------------ cursor

    fn peek(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    fn peek_span(&self) -> Span {
        self.tokens[self.pos].span
    }

    /// Byte just past the previous token; used to close spans.
    fn prev_end(&self) -> usize {
        if self.pos == 0 { 0 } else { self.tokens[self.pos - 1].span.end }
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        if !matches!(t.kind, TokenKind::Eof) {
            self.pos += 1;
        }
        t
    }

    fn at(&self, kind: &TokenKind) -> bool {
        self.peek() == kind
    }

    fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn error<T>(&self, message: impl Into<String>, span: Span) -> PResult<T> {
        Err(ParseError { message: message.into(), span })
    }

    fn unexpected<T>(&self, expected: &str) -> PResult<T> {
        let msg = format!("expected {expected}, found {}", describe(self.peek()));
        self.error(msg, self.peek_span())
    }

    fn expect(&mut self, kind: TokenKind, what: &str) -> PResult<Token> {
        if self.at(&kind) { Ok(self.advance()) } else { self.unexpected(what) }
    }

    fn expect_ident(&mut self, what: &str) -> PResult<Ident> {
        match self.peek() {
            TokenKind::Ident(name) => {
                let name = name.clone();
                let span = self.advance().span;
                Ok(Ident { name, span })
            }
            _ => self.unexpected(what),
        }
    }

    fn expect_int(&mut self, what: &str) -> PResult<u64> {
        match self.peek() {
            TokenKind::Int(n) => {
                let n = *n;
                self.advance();
                Ok(n)
            }
            _ => self.unexpected(what),
        }
    }

    fn expect_str(&mut self, what: &str) -> PResult<String> {
        match self.peek() {
            TokenKind::Str(s) => {
                let s = s.clone();
                self.advance();
                Ok(s)
            }
            _ => self.unexpected(what),
        }
    }

    /// Consume a `>`. If the next token is `>>`, consume only its first
    /// half and leave a `>` behind for the next caller.
    fn expect_gt(&mut self) -> PResult<()> {
        match self.peek() {
            TokenKind::Gt => {
                self.advance();
                Ok(())
            }
            TokenKind::Shr => {
                let span = self.peek_span();
                self.tokens[self.pos] = Token { kind: TokenKind::Gt, span: Span::new(span.start + 1, span.end) };
                Ok(())
            }
            _ => self.unexpected("`>`"),
        }
    }

    // ------------------------------------------------------------- items

    fn program(&mut self) -> PResult<Program> {
        let mut items = Vec::new();
        while !self.at(&TokenKind::Eof) {
            items.push(self.item()?);
        }
        Ok(Program { items })
    }

    fn item(&mut self) -> PResult<Item> {
        match self.peek() {
            TokenKind::Const => self.const_decl().map(Item::Const),
            TokenKind::Map => self.map_decl().map(Item::Map),
            TokenKind::Event => self.event_decl().map(Item::Event),
            TokenKind::Probe => self.probe_decl().map(Item::Probe),
            _ => self.unexpected("an item (`const`, `map`, `event`, or `probe`)"),
        }
    }

    fn const_decl(&mut self) -> PResult<ConstDecl> {
        let start = self.expect(TokenKind::Const, "`const`")?.span.start;
        let name = self.expect_ident("constant name")?;
        self.expect(TokenKind::Colon, "`:`")?;
        let ty = self.ty()?;
        self.expect(TokenKind::Eq, "`=`")?;
        let value = self.expr()?;
        self.expect(TokenKind::Semi, "`;`")?;
        Ok(ConstDecl { name, ty, value, span: Span::new(start, self.prev_end()) })
    }

    fn map_decl(&mut self) -> PResult<MapDecl> {
        let start = self.expect(TokenKind::Map, "`map`")?.span.start;
        let name = self.expect_ident("map name")?;
        self.expect(TokenKind::Colon, "`:`")?;
        let kind = self.expect_ident("map kind (`hash` or `array`)")?;
        self.expect(TokenKind::Lt, "`<`")?;
        let mut args = vec![self.ty()?];
        while self.eat(&TokenKind::Comma) {
            args.push(self.ty()?);
        }
        self.expect_gt()?;
        self.expect(TokenKind::LBracket, "`[`")?;
        let capacity = self.expect_int("map capacity")?;
        self.expect(TokenKind::RBracket, "`]`")?;
        self.expect(TokenKind::Semi, "`;`")?;
        Ok(MapDecl { name, kind, args, capacity, span: Span::new(start, self.prev_end()) })
    }

    fn event_decl(&mut self) -> PResult<EventDecl> {
        let start = self.expect(TokenKind::Event, "`event`")?.span.start;
        let name = self.expect_ident("event name")?;
        self.expect(TokenKind::LBrace, "`{`")?;
        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) {
            let fname = self.expect_ident("field name")?;
            self.expect(TokenKind::Colon, "`:`")?;
            let ty = self.ty()?;
            let span = Span::new(fname.span.start, self.prev_end());
            fields.push(Field { name: fname, ty, span });
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::RBrace, "`}` or `,`")?;
        Ok(EventDecl { name, fields, span: Span::new(start, self.prev_end()) })
    }

    fn probe_decl(&mut self) -> PResult<ProbeDecl> {
        let start = self.expect(TokenKind::Probe, "`probe`")?.span.start;
        let kind = self.expect_ident("probe kind (e.g. `tracepoint`)")?;
        self.expect(TokenKind::LParen, "`(`")?;
        let mut args = vec![self.expect_str("a string argument")?];
        while self.eat(&TokenKind::Comma) {
            args.push(self.expect_str("a string argument")?);
        }
        self.expect(TokenKind::RParen, "`)`")?;
        let body = self.block()?;
        Ok(ProbeDecl { kind, args, body, span: Span::new(start, self.prev_end()) })
    }

    // ------------------------------------------------------------- types

    fn ty(&mut self) -> PResult<Type> {
        let name = self.expect_ident("a type")?;
        let start = name.span.start;
        let mut args = Vec::new();
        if self.eat(&TokenKind::Lt) {
            loop {
                let arg = match self.peek() {
                    TokenKind::Int(_) => TypeArg::Int(self.expect_int("integer")?),
                    _ => TypeArg::Type(self.ty()?),
                };
                args.push(arg);
                if !self.eat(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect_gt()?;
        }
        Ok(Type { name, args, span: Span::new(start, self.prev_end()) })
    }

    // -------------------------------------------------------- statements

    fn block(&mut self) -> PResult<Block> {
        let start = self.expect(TokenKind::LBrace, "`{`")?.span.start;
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::RBrace) {
            if self.at(&TokenKind::Eof) {
                return self.error("unclosed block: expected `}`", Span::new(start, start + 1));
            }
            stmts.push(self.stmt()?);
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(Block { stmts, span: Span::new(start, self.prev_end()) })
    }

    fn stmt(&mut self) -> PResult<Stmt> {
        let start = self.peek_span().start;
        let kind = match self.peek() {
            TokenKind::Let => self.let_stmt()?,
            TokenKind::If => self.if_stmt()?,
            TokenKind::For => self.for_stmt()?,
            TokenKind::Emit => self.emit_stmt()?,
            TokenKind::Return => self.return_stmt()?,
            TokenKind::While => {
                return self.error("`while` is not allowed: loops must have a constant bound, use `for i in a..b`", self.peek_span());
            }
            _ => self.expr_or_assign_stmt()?,
        };
        Ok(Stmt { kind, span: Span::new(start, self.prev_end()) })
    }

    fn let_stmt(&mut self) -> PResult<StmtKind> {
        self.expect(TokenKind::Let, "`let`")?;
        let mutable = self.eat(&TokenKind::Mut);
        let name = self.expect_ident("variable name")?;
        let ty = if self.eat(&TokenKind::Colon) { Some(self.ty()?) } else { None };
        self.expect(TokenKind::Eq, "`=`")?;
        let value = self.expr()?;
        self.expect(TokenKind::Semi, "`;`")?;
        Ok(StmtKind::Let { mutable, name, ty, value })
    }

    fn if_stmt(&mut self) -> PResult<StmtKind> {
        self.expect(TokenKind::If, "`if`")?;
        let cond = if self.eat(&TokenKind::Let) {
            let pattern = self.pattern()?;
            self.expect(TokenKind::Eq, "`=`")?;
            let value = self.expr()?;
            Cond::Let { pattern, value }
        } else {
            Cond::Expr(self.expr()?)
        };
        let then = self.block()?;
        let otherwise = if self.eat(&TokenKind::Else) {
            if self.at(&TokenKind::If) {
                // `else if ...` becomes an else-block holding one `if`.
                let start = self.peek_span().start;
                let kind = self.if_stmt()?;
                let span = Span::new(start, self.prev_end());
                Some(Block { stmts: vec![Stmt { kind, span }], span })
            } else {
                Some(self.block()?)
            }
        } else {
            None
        };
        Ok(StmtKind::If { cond, then, otherwise })
    }

    fn pattern(&mut self) -> PResult<Pattern> {
        let name = self.expect_ident("a pattern (`Some(x)` or `None`)")?;
        let start = name.span.start;
        let binding = if self.eat(&TokenKind::LParen) {
            let b = self.expect_ident("binding name")?;
            self.expect(TokenKind::RParen, "`)`")?;
            Some(b)
        } else {
            None
        };
        Ok(Pattern { name, binding, span: Span::new(start, self.prev_end()) })
    }

    fn for_stmt(&mut self) -> PResult<StmtKind> {
        self.expect(TokenKind::For, "`for`")?;
        let var = self.expect_ident("loop variable")?;
        self.expect(TokenKind::In, "`in`")?;
        let start = self.expr()?;
        self.expect(TokenKind::DotDot, "`..`")?;
        let end = self.expr()?;
        let body = self.block()?;
        Ok(StmtKind::For { var, start, end, body })
    }

    fn emit_stmt(&mut self) -> PResult<StmtKind> {
        self.expect(TokenKind::Emit, "`emit`")?;
        let event = self.expect_ident("event name")?;
        self.expect(TokenKind::LBrace, "`{`")?;
        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) {
            let name = self.expect_ident("field name")?;
            self.expect(TokenKind::Colon, "`:`")?;
            let value = self.expr()?;
            fields.push((name, value));
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::RBrace, "`}` or `,`")?;
        self.expect(TokenKind::Semi, "`;`")?;
        Ok(StmtKind::Emit { event, fields })
    }

    fn return_stmt(&mut self) -> PResult<StmtKind> {
        self.expect(TokenKind::Return, "`return`")?;
        let value = if self.at(&TokenKind::Semi) { None } else { Some(self.expr()?) };
        self.expect(TokenKind::Semi, "`;`")?;
        Ok(StmtKind::Return(value))
    }

    fn expr_or_assign_stmt(&mut self) -> PResult<StmtKind> {
        let e = self.expr()?;
        if self.eat(&TokenKind::Eq) {
            if !is_place(&e) {
                return self.error("invalid assignment target: expected a name, `*name`, or `view.field`", e.span);
            }
            let value = self.expr()?;
            self.expect(TokenKind::Semi, "`;`")?;
            return Ok(StmtKind::Assign { target: e, value });
        }
        self.expect(TokenKind::Semi, "`;`")?;
        Ok(StmtKind::Expr(e))
    }

    // ------------------------------------------------------- expressions

    pub(crate) fn expr(&mut self) -> PResult<Expr> {
        self.binary(0)
    }

    /// Precedence climbing. `min_bp` is the lowest binding power we are
    /// willing to consume an operator at.
    fn binary(&mut self, min_bp: u8) -> PResult<Expr> {
        let mut lhs = self.cast()?;
        while let Some((op, bp)) = binary_op(self.peek()) {
            if bp < min_bp {
                break;
            }
            self.advance();
            // Left-associative: the right operand binds strictly tighter.
            let rhs = self.binary(bp + 1)?;
            let span = Span::new(lhs.span.start, rhs.span.end);
            lhs = Expr { kind: ExprKind::Binary { op, lhs: Box::new(lhs), rhs: Box::new(rhs) }, span };
        }
        Ok(lhs)
    }

    fn cast(&mut self) -> PResult<Expr> {
        let mut e = self.unary()?;
        while self.eat(&TokenKind::As) {
            let ty = self.ty()?;
            let span = Span::new(e.span.start, ty.span.end);
            e = Expr { kind: ExprKind::Cast { expr: Box::new(e), ty }, span };
        }
        Ok(e)
    }

    fn unary(&mut self) -> PResult<Expr> {
        let op = match self.peek() {
            TokenKind::Bang => UnaryOp::Not,
            TokenKind::Minus => UnaryOp::Neg,
            TokenKind::Tilde => UnaryOp::BitNot,
            TokenKind::Star => UnaryOp::Deref,
            _ => return self.postfix(),
        };
        let start = self.advance().span.start;
        let operand = self.unary()?;
        let span = Span::new(start, operand.span.end);
        Ok(Expr { kind: ExprKind::Unary { op, expr: Box::new(operand) }, span })
    }

    fn postfix(&mut self) -> PResult<Expr> {
        let mut e = self.primary()?;
        loop {
            match self.peek() {
                TokenKind::LParen => {
                    let args = self.args()?;
                    let span = Span::new(e.span.start, self.prev_end());
                    e = Expr { kind: ExprKind::Call { callee: Box::new(e), args }, span };
                }
                TokenKind::Dot => {
                    self.advance();
                    let name = self.expect_ident("field or method name")?;
                    let kind = if self.at(&TokenKind::LParen) {
                        let args = self.args()?;
                        ExprKind::MethodCall { receiver: Box::new(e), method: name, args }
                    } else {
                        ExprKind::Field { expr: Box::new(e), field: name }
                    };
                    let span = Span::new(span_start(&kind), self.prev_end());
                    e = Expr { kind, span };
                }
                TokenKind::LBracket => {
                    self.advance();
                    let index = self.expr()?;
                    self.expect(TokenKind::RBracket, "`]`")?;
                    let span = Span::new(e.span.start, self.prev_end());
                    e = Expr { kind: ExprKind::Index { expr: Box::new(e), index: Box::new(index) }, span };
                }
                _ => break,
            }
        }
        Ok(e)
    }

    fn args(&mut self) -> PResult<Vec<Expr>> {
        self.expect(TokenKind::LParen, "`(`")?;
        let mut args = Vec::new();
        while !self.at(&TokenKind::RParen) {
            args.push(self.expr()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::RParen, "`)` or `,`")?;
        Ok(args)
    }

    fn primary(&mut self) -> PResult<Expr> {
        let span = self.peek_span();
        let kind = match self.peek() {
            TokenKind::Int(n) => ExprKind::Int(*n),
            TokenKind::Str(s) => ExprKind::Str(s.clone()),
            TokenKind::True => ExprKind::Bool(true),
            TokenKind::False => ExprKind::Bool(false),
            TokenKind::Ident(name) => ExprKind::Ident(name.clone()),
            TokenKind::LParen => {
                self.advance();
                let inner = self.expr()?;
                self.expect(TokenKind::RParen, "`)`")?;
                // Keep the inner node; parens only affect grouping.
                return Ok(Expr { kind: inner.kind, span: Span::new(span.start, self.prev_end()) });
            }
            _ => return self.unexpected("an expression"),
        };
        self.advance();
        Ok(Expr { kind, span })
    }
}

/// The start byte of the receiver/expr inside a freshly built postfix node.
fn span_start(kind: &ExprKind) -> usize {
    match kind {
        ExprKind::MethodCall { receiver, .. } => receiver.span.start,
        ExprKind::Field { expr, .. } => expr.span.start,
        _ => unreachable!("only called for method/field nodes"),
    }
}

/// Binary operators and their binding power (higher binds tighter).
fn binary_op(kind: &TokenKind) -> Option<(BinaryOp, u8)> {
    use BinaryOp::*;
    Some(match kind {
        TokenKind::PipePipe => (Or, 1),
        TokenKind::AmpAmp => (And, 2),
        TokenKind::EqEq => (Eq, 3),
        TokenKind::BangEq => (Ne, 3),
        TokenKind::Lt => (Lt, 4),
        TokenKind::LtEq => (Le, 4),
        TokenKind::Gt => (Gt, 4),
        TokenKind::GtEq => (Ge, 4),
        TokenKind::Pipe => (BitOr, 5),
        TokenKind::Caret => (BitXor, 6),
        TokenKind::Amp => (BitAnd, 7),
        TokenKind::Shl => (Shl, 8),
        TokenKind::Shr => (Shr, 8),
        TokenKind::Plus => (Add, 9),
        TokenKind::Minus => (Sub, 9),
        TokenKind::Star => (Mul, 10),
        TokenKind::Slash => (Div, 10),
        TokenKind::Percent => (Rem, 10),
        _ => return None,
    })
}

/// Can this expression be assigned to?
fn is_place(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Ident(_) => true,
        ExprKind::Unary { op: UnaryOp::Deref, expr } => matches!(expr.kind, ExprKind::Ident(_)),
        // `view.field = v` (the type checker decides whether the view is writable)
        ExprKind::Field { expr, .. } => matches!(expr.kind, ExprKind::Ident(_) | ExprKind::Field { .. }),
        _ => false,
    }
}

/// Human-readable name of a token for error messages.
fn describe(kind: &TokenKind) -> String {
    use TokenKind::*;
    match kind {
        Ident(name) => format!("identifier `{name}`"),
        Int(n) => format!("integer `{n}`"),
        Str(s) => format!("string {s:?}"),
        Eof => "end of input".to_string(),
        Probe => "`probe`".into(),
        Map => "`map`".into(),
        Event => "`event`".into(),
        Const => "`const`".into(),
        Let => "`let`".into(),
        Mut => "`mut`".into(),
        If => "`if`".into(),
        Else => "`else`".into(),
        For => "`for`".into(),
        In => "`in`".into(),
        Emit => "`emit`".into(),
        Return => "`return`".into(),
        True => "`true`".into(),
        False => "`false`".into(),
        As => "`as`".into(),
        Fn => "`fn`".into(),
        Struct => "`struct`".into(),
        Match => "`match`".into(),
        While => "`while`".into(),
        Break => "`break`".into(),
        Continue => "`continue`".into(),
        LParen => "`(`".into(),
        RParen => "`)`".into(),
        LBrace => "`{`".into(),
        RBrace => "`}`".into(),
        LBracket => "`[`".into(),
        RBracket => "`]`".into(),
        Comma => "`,`".into(),
        Semi => "`;`".into(),
        Colon => "`:`".into(),
        ColonColon => "`::`".into(),
        Dot => "`.`".into(),
        DotDot => "`..`".into(),
        Arrow => "`->`".into(),
        Eq => "`=`".into(),
        EqEq => "`==`".into(),
        Bang => "`!`".into(),
        BangEq => "`!=`".into(),
        Lt => "`<`".into(),
        LtEq => "`<=`".into(),
        Gt => "`>`".into(),
        GtEq => "`>=`".into(),
        Plus => "`+`".into(),
        Minus => "`-`".into(),
        Star => "`*`".into(),
        Slash => "`/`".into(),
        Percent => "`%`".into(),
        Amp => "`&`".into(),
        AmpAmp => "`&&`".into(),
        Pipe => "`|`".into(),
        PipePipe => "`||`".into(),
        Caret => "`^`".into(),
        Tilde => "`~`".into(),
        Shl => "`<<`".into(),
        Shr => "`>>`".into(),
    }
}
