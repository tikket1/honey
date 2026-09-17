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
//! - `typeck`  : stage 4, the verifier-aware type checker (runs before codegen)
//! - `codegen` : stage 3, AST → BPF bytecode

pub mod addr;
pub mod ast;
pub mod bpf;
pub mod btf;
pub mod codegen;
pub mod layout;
pub mod lexer;
pub mod parser;
pub mod pretty;
pub mod token;
pub mod typeck;
