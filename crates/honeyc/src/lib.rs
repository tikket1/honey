//! honeyc — the honey compiler.
//!
//!   source text ─lexer→ tokens ─parser→ AST ─codegen→ BPF bytecode
//!
//! - `token`   : token vocabulary (lexer ⇄ parser contract)
//! - `lexer`   : stage 1, text → tokens
//! - `ast`     : the tree shape (parser ⇄ later stages contract)
//! - `parser`  : stage 2, tokens → AST
//! - `pretty`  : AST → text, for debugging and round-trip tests
//! - `bpf`     : eBPF instruction encoding + disassembly (the machine)
//! - `layout`  : event record byte layout
//! - `codegen` : stage 3, AST → BPF bytecode (first slice)

pub mod ast;
pub mod bpf;
pub mod codegen;
pub mod layout;
pub mod lexer;
pub mod parser;
pub mod pretty;
pub mod token;
