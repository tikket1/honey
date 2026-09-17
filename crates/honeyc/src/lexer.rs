//! Stage 1: turn source text into tokens.
//!
//! Your job is to make `lex` satisfy `tests/lexer.rs`. Read
//! `docs/STAGE-1.md` first, then `docs/LANGUAGE.md` § "Lexical structure".
//!
//! Suggested shape (delete this and do it your own way if you prefer):
//!
//! ```ignore
//! struct Lexer<'a> {
//!     src: &'a str,   // the whole input
//!     pos: usize,     // byte offset of the next unread character
//!     tokens: Vec<Token>,
//! }
//!
//! impl<'a> Lexer<'a> {
//!     fn peek(&self) -> Option<char> { ... }   // look, don't consume
//!     fn bump(&mut self) -> Option<char> { ... } // consume one char
//!     fn lex_ident_or_keyword(&mut self, start: usize) { ... }
//!     fn lex_number(&mut self, start: usize) -> Result<(), LexError> { ... }
//!     fn lex_string(&mut self, start: usize) -> Result<(), LexError> { ... }
//!     fn skip_block_comment(&mut self, start: usize) -> Result<(), LexError> { ... }
//! }
//! ```

use crate::token::{LexError, Token};

/// Tokenize `src`. On success the returned vector always ends with
/// `TokenKind::Eof`. On failure, the *first* error encountered is returned.
pub fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let _ = src;
    todo!("stage 1: implement the lexer (see docs/STAGE-1.md)")
}
