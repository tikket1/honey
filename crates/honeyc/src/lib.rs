//! honeyc — the honey compiler.
//!
//! Pipeline (one module per stage, added as each stage is built):
//!
//!   source text ──lexer──▶ tokens ──parser──▶ AST ──typeck──▶ typed AST ──codegen──▶ BPF bytecode
//!
//! - `token`  : the token vocabulary (lexer ⇄ parser contract)
//! - `lexer`  : stage 1, text → tokens
//! - `ast`    : the tree shape (parser ⇄ later stages contract)
//! - `parser` : stage 2, tokens → AST
//! - `pretty` : AST → text, for debugging and round-trip tests

pub mod ast;
pub mod lexer;
pub mod parser;
pub mod pretty;
pub mod token;
