//! Stage 1: turn source text into tokens.
//!
//! The lexer walks the source left to right, one character at a time, and
//! groups characters into `Token`s. It never looks more than two characters
//! ahead, and it never backtracks. The rules it follows are written down in
//! `docs/LANGUAGE.md` § 3; every branch below corresponds to a rule there.
//!
//! Positions are **byte** offsets into the source. All of honey's tokens are
//! ASCII, so most of the time one byte is one character; the only places a
//! multi-byte character can show up are inside string literals and comments
//! (where we just copy it through) and as an `UnexpectedChar` error (where
//! we need its full width for the span). `char::len_utf8` handles both.

use crate::token::{LexError, LexErrorKind, Span, Token, TokenKind};

/// Tokenize `src`. On success the returned vector always ends with
/// `TokenKind::Eof`. On failure, the *first* error encountered is returned.
pub fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let mut lexer = Lexer { src, pos: 0, tokens: Vec::new() };
    lexer.run()?;
    Ok(lexer.tokens)
}

/// The lexer's whole state: the text, how far we've read, and what we've
/// produced so far. `'a` says the struct borrows `src` and can't outlive it.
struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    tokens: Vec<Token>,
}

impl<'a> Lexer<'a> {
    // ------------------------------------------------------------ cursor

    /// The next unread character, without consuming it.
    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    /// The character after `peek()`, without consuming anything.
    fn peek_second(&self) -> Option<char> {
        let mut chars = self.src[self.pos..].chars();
        chars.next();
        chars.next()
    }

    /// Consume and return the next character. Advances by its byte width.
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    /// Consume the next character only if it is `expected`.
    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.bump();
            true
        } else {
            false
        }
    }

    /// Keep consuming while `keep_going` says yes.
    fn bump_while(&mut self, keep_going: impl Fn(char) -> bool) {
        while let Some(c) = self.peek() {
            if !keep_going(c) {
                break;
            }
            self.bump();
        }
    }

    // ------------------------------------------------------------ output

    /// Record a token that started at byte `start` and ends at the cursor.
    fn push(&mut self, kind: TokenKind, start: usize) {
        self.tokens.push(Token { kind, span: Span::new(start, self.pos) });
    }

    /// Build an error whose span runs from `start` to the cursor.
    fn error(&self, kind: LexErrorKind, start: usize) -> LexError {
        LexError { kind, span: Span::new(start, self.pos) }
    }

    // --------------------------------------------------------- main loop

    fn run(&mut self) -> Result<(), LexError> {
        while let Some(c) = self.peek() {
            let start = self.pos;
            match c {
                ' ' | '\t' | '\n' | '\r' => {
                    self.bump();
                }
                '/' if self.peek_second() == Some('/') => self.skip_line_comment(),
                '/' if self.peek_second() == Some('*') => self.skip_block_comment(start)?,
                'a'..='z' | 'A'..='Z' | '_' => self.lex_ident_or_keyword(start),
                '0'..='9' => self.lex_number(start)?,
                '"' => self.lex_string(start)?,
                _ => self.lex_punctuation(start)?,
            }
        }
        let end = self.src.len();
        self.tokens.push(Token { kind: TokenKind::Eof, span: Span::new(end, end) });
        Ok(())
    }

    // ---------------------------------------------------------- comments

    fn skip_line_comment(&mut self) {
        self.bump_while(|c| c != '\n');
        // The '\n' itself is left for the main loop to skip as whitespace.
    }

    /// `/* ... */`, nesting allowed. `start` is the byte of the opening `/`.
    fn skip_block_comment(&mut self, start: usize) -> Result<(), LexError> {
        self.bump(); // '/'
        self.bump(); // '*'
        let mut depth = 1;
        while depth > 0 {
            match (self.peek(), self.peek_second()) {
                (None, _) => return Err(self.error(LexErrorKind::UnterminatedComment, start)),
                (Some('/'), Some('*')) => {
                    self.bump();
                    self.bump();
                    depth += 1;
                }
                (Some('*'), Some('/')) => {
                    self.bump();
                    self.bump();
                    depth -= 1;
                }
                _ => {
                    self.bump();
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------ identifiers/keywords

    fn lex_ident_or_keyword(&mut self, start: usize) {
        self.bump_while(|c| c.is_ascii_alphanumeric() || c == '_');
        let word = &self.src[start..self.pos];
        let kind = match keyword(word) {
            Some(kw) => kw,
            None => TokenKind::Ident(word.to_string()),
        };
        self.push(kind, start);
    }

    // ----------------------------------------------------------- numbers

    fn lex_number(&mut self, start: usize) -> Result<(), LexError> {
        // Pick the radix from an optional 0x / 0b / 0o prefix.
        let radix = match (self.peek(), self.peek_second()) {
            (Some('0'), Some('x')) => 16,
            (Some('0'), Some('b')) => 2,
            (Some('0'), Some('o')) => 8,
            _ => 10,
        };
        if radix != 10 {
            self.bump();
            self.bump();
        }

        let digits_start = self.pos;
        self.bump_while(|c| c == '_' || c.is_digit(radix));

        // `_` is only a visual separator; strip it before parsing.
        let digits: String = self.src[digits_start..self.pos]
            .chars()
            .filter(|&c| c != '_')
            .collect();

        match u64::from_str_radix(&digits, radix) {
            Ok(value) => {
                self.push(TokenKind::Int(value), start);
                Ok(())
            }
            Err(_) => Err(self.error(LexErrorKind::IntegerOverflow, start)),
        }
    }

    // ----------------------------------------------------------- strings

    /// `"..."` with escapes decoded. `start` is the byte of the opening quote.
    fn lex_string(&mut self, start: usize) -> Result<(), LexError> {
        self.bump(); // opening '"'
        let mut value = String::new();
        loop {
            match self.bump() {
                None => return Err(self.error(LexErrorKind::UnterminatedString, start)),
                Some('"') => break,
                Some('\\') => {
                    let escape_start = self.pos - 1;
                    let decoded = match self.bump() {
                        Some('n') => '\n',
                        Some('t') => '\t',
                        Some('r') => '\r',
                        Some('\\') => '\\',
                        Some('"') => '"',
                        Some('0') => '\0',
                        Some('x') => self.lex_hex_escape(escape_start)?,
                        _ => return Err(self.error(LexErrorKind::InvalidEscape, escape_start)),
                    };
                    value.push(decoded);
                }
                Some(c) => value.push(c),
            }
        }
        self.push(TokenKind::Str(value), start);
        Ok(())
    }

    /// The `NN` part of `\xNN`, already past the `x`.
    fn lex_hex_escape(&mut self, escape_start: usize) -> Result<char, LexError> {
        let hi = self.bump().and_then(|c| c.to_digit(16));
        let lo = self.bump().and_then(|c| c.to_digit(16));
        match (hi, lo) {
            (Some(hi), Some(lo)) => Ok(char::from((hi * 16 + lo) as u8)),
            _ => Err(self.error(LexErrorKind::InvalidEscape, escape_start)),
        }
    }

    // ------------------------------------------------------- punctuation

    /// Everything that isn't whitespace, a word, a number, or a string.
    /// Longest match wins: `==` before `=`, `..` before `.`, and so on.
    fn lex_punctuation(&mut self, start: usize) -> Result<(), LexError> {
        use TokenKind::*;

        // Safe to unwrap: the main loop only calls us when peek() is Some.
        let c = self.bump().unwrap();

        let kind = match c {
            '(' => LParen,
            ')' => RParen,
            '{' => LBrace,
            '}' => RBrace,
            '[' => LBracket,
            ']' => RBracket,
            ',' => Comma,
            ';' => Semi,
            '+' => Plus,
            '*' => Star,
            '/' => Slash,
            '%' => Percent,
            '^' => Caret,
            '~' => Tilde,

            ':' if self.eat(':') => ColonColon,
            ':' => Colon,
            '.' if self.eat('.') => DotDot,
            '.' => Dot,
            '-' if self.eat('>') => Arrow,
            '-' => Minus,
            '=' if self.eat('=') => EqEq,
            '=' => Eq,
            '!' if self.eat('=') => BangEq,
            '!' => Bang,
            '&' if self.eat('&') => AmpAmp,
            '&' => Amp,
            '|' if self.eat('|') => PipePipe,
            '|' => Pipe,
            '<' if self.eat('=') => LtEq,
            '<' if self.eat('<') => Shl,
            '<' => Lt,
            '>' if self.eat('=') => GtEq,
            '>' if self.eat('>') => Shr,
            '>' => Gt,

            other => return Err(self.error(LexErrorKind::UnexpectedChar(other), start)),
        };
        self.push(kind, start);
        Ok(())
    }
}

/// The keyword table. Anything not listed here is an identifier.
fn keyword(word: &str) -> Option<TokenKind> {
    use TokenKind::*;
    Some(match word {
        "probe" => Probe,
        "map" => Map,
        "event" => Event,
        "const" => Const,
        "let" => Let,
        "mut" => Mut,
        "if" => If,
        "else" => Else,
        "for" => For,
        "in" => In,
        "emit" => Emit,
        "return" => Return,
        "true" => True,
        "false" => False,
        "as" => As,
        // reserved
        "fn" => Fn,
        "struct" => Struct,
        "match" => Match,
        "while" => While,
        "break" => Break,
        "continue" => Continue,
        _ => return None,
    })
}
