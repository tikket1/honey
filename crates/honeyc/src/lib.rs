//! honeyc — the honey compiler.
//!
//! Pipeline (one module per stage, added as each stage is built):
//!
//!   source text ──lexer──▶ tokens ──parser──▶ AST ──typeck──▶ typed AST ──codegen──▶ BPF bytecode
//!
//! Stage 1 is `lexer`. The token vocabulary it must produce lives in `token`.

pub mod lexer;
pub mod token;
