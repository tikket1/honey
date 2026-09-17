//! honeyc command line.
//!
//!   honeyc <file.hny>                 parse and pretty-print
//!   honeyc --tokens <file.hny>        dump the token stream
//!   honeyc --asm <file.hny>           compile and show BPF assembly
//!   honeyc build <file.hny> -o <out>  write <out>.bin (bytecode) + <out>.json (manifest)

use std::{env, fs, process};

use honeyc::bpf;
use honeyc::codegen::{self, Compiled};
use honeyc::layout::FieldKind;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let strs: Vec<&str> = args.iter().map(String::as_str).collect();
    let code = match strs.as_slice() {
        ["--tokens", path] => cmd_tokens(path),
        ["--asm", path] => cmd_asm(path),
        ["build", path, "-o", out] => cmd_build(path, out),
        [path] if !path.starts_with('-') => cmd_pretty(path),
        _ => {
            eprintln!("usage: honeyc [--tokens|--asm] <file.hny>");
            eprintln!("       honeyc build <file.hny> -o <out>");
            2
        }
    };
    process::exit(code);
}

fn read(path: &str) -> String {
    match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{path}: {e}");
            process::exit(1);
        }
    }
}

fn cmd_tokens(path: &str) -> i32 {
    let src = read(path);
    match honeyc::lexer::lex(&src) {
        Ok(tokens) => {
            for t in tokens {
                println!("{:>4}..{:<4} {:?}", t.span.start, t.span.end, t.kind);
            }
            0
        }
        Err(e) => {
            report(path, &src, e.span.start, &format!("{:?}", e.kind));
            1
        }
    }
}

fn cmd_pretty(path: &str) -> i32 {
    let src = read(path);
    match honeyc::parser::parse(&src) {
        Ok(program) => {
            print!("{}", honeyc::pretty::program(&program));
            0
        }
        Err(e) => {
            report(path, &src, e.span().start, &e.message());
            1
        }
    }
}

fn cmd_asm(path: &str) -> i32 {
    let src = read(path);
    match compile(path, &src) {
        Some(c) => {
            let insns = decode_all(&c.bytecode);
            print!("{}", bpf::disasm_prog(&insns));
            0
        }
        None => 1,
    }
}

fn cmd_build(path: &str, out: &str) -> i32 {
    let src = read(path);
    let Some(c) = compile(path, &src) else { return 1 };

    let bin = format!("{out}.bin");
    let json = format!("{out}.json");
    if let Err(e) = fs::write(&bin, &c.bytecode) {
        eprintln!("{bin}: {e}");
        return 1;
    }
    if let Err(e) = fs::write(&json, manifest(&c)) {
        eprintln!("{json}: {e}");
        return 1;
    }
    eprintln!(
        "wrote {bin} ({} bytes, {} instructions) and {json}",
        c.bytecode.len(),
        c.bytecode.len() / 8
    );
    0
}

/// Lex, parse, and run codegen; report errors against the source.
fn compile(path: &str, src: &str) -> Option<Compiled> {
    let program = match honeyc::parser::parse(src) {
        Ok(p) => p,
        Err(e) => {
            report(path, src, e.span().start, &e.message());
            return None;
        }
    };
    match codegen::compile(&program) {
        Ok(c) => Some(c),
        Err(msg) => {
            eprintln!("{path}: codegen error: {msg}");
            None
        }
    }
}

fn decode_all(bytes: &[u8]) -> Vec<bpf::Insn> {
    // Re-decode our own bytes so --asm exercises the same path the loader
    // will. LD_IMM64 (opcode 0x18) spans two 8-byte slots.
    let mut insns = Vec::new();
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let opcode = bytes[i];
        let dst = bytes[i + 1] & 0x0f;
        let src = bytes[i + 1] >> 4;
        let off = i16::from_le_bytes([bytes[i + 2], bytes[i + 3]]);
        let imm = i32::from_le_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]);
        if opcode == 0x18 && i + 16 <= bytes.len() {
            let imm_high = i32::from_le_bytes([bytes[i + 12], bytes[i + 13], bytes[i + 14], bytes[i + 15]]);
            insns.push(bpf::Insn::from_parts(opcode, dst, src, off, imm, Some(imm_high)));
            i += 16;
        } else {
            insns.push(bpf::Insn::from_parts(opcode, dst, src, off, imm, None));
            i += 8;
        }
    }
    insns
}

/// Hand-rolled JSON so the compiler keeps its zero-dependency promise.
fn manifest(c: &Compiled) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"license\": {},\n", jstr(&c.license)));
    s.push_str("  \"prog_type\": \"tracepoint\",\n");
    s.push_str(&format!(
        "  \"tracepoint\": {{ \"category\": {}, \"name\": {} }},\n",
        jstr(&c.tracepoint.0),
        jstr(&c.tracepoint.1)
    ));
    s.push_str(&format!("  \"ringbuf_bytes\": {},\n", c.ringbuf_bytes));
    s.push_str(&format!("  \"event\": {{ \"name\": {}, \"size\": {}, \"fields\": [\n", jstr(&c.event.name), c.event.size));
    for (i, f) in c.event.fields.iter().enumerate() {
        let (kind, extra) = match &f.kind {
            FieldKind::Uint(w) => ("uint", format!("\"width\": {w}")),
            FieldKind::Str(n) => ("str", format!("\"cap\": {n}")),
            FieldKind::Bool => ("bool", "\"width\": 1".to_string()),
        };
        let comma = if i + 1 < c.event.fields.len() { "," } else { "" };
        s.push_str(&format!(
            "    {{ \"name\": {}, \"offset\": {}, \"size\": {}, \"kind\": \"{}\", {} }}{}\n",
            jstr(&f.name), f.offset, f.size, kind, extra, comma
        ));
    }
    s.push_str("  ] }\n}\n");
    s
}

fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Print `path:line:col: error: message` plus the offending source line.
fn report(path: &str, src: &str, offset: usize, message: &str) {
    let before = &src[..offset.min(src.len())];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let col = offset - line_start + 1;
    let line_text = src[line_start..].lines().next().unwrap_or("");
    eprintln!("{path}:{line}:{col}: error: {message}");
    eprintln!("    {line_text}");
    eprintln!("    {}^", " ".repeat(col.saturating_sub(1)));
}
