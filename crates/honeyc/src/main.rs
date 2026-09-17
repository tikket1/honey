//! honeyc command line.
//!
//!   honeyc <file.hny>                 parse and pretty-print
//!   honeyc check <file.hny>           type-check only (verifier rules, at your source line)
//!   honeyc --tokens <file.hny>        dump the token stream
//!   honeyc --asm <file.hny>           check, compile, and show BPF assembly
//!   honeyc build <file.hny> -o <out>  check, compile, write <out>.bin + <out>.json
//!
//! `--arch aarch64|x86_64` (default aarch64) selects the kprobe register
//! layout; it must match the kernel the loader runs on.

use std::{env, fs, process};

use honeyc::bpf;
use honeyc::codegen::{self, Arch, Compiled, MapKind, ProbeKind};
use honeyc::layout::FieldKind;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    // Pull out `--arch X` wherever it appears.
    let mut arch = Arch::Aarch64;
    if let Some(i) = args.iter().position(|a| a == "--arch") {
        let Some(name) = args.get(i + 1) else {
            eprintln!("--arch needs a value: aarch64 or x86_64");
            process::exit(2);
        };
        match Arch::parse(name) {
            Some(a) => arch = a,
            None => {
                eprintln!("unknown arch `{name}`: use aarch64 or x86_64");
                process::exit(2);
            }
        }
        args.drain(i..i + 2);
    }
    let strs: Vec<&str> = args.iter().map(String::as_str).collect();
    let code = match strs.as_slice() {
        ["--tokens", path] => cmd_tokens(path),
        ["check", path] => cmd_check(path),
        ["--asm", path] => cmd_asm(path, arch),
        ["build", path, "-o", out] => cmd_build(path, out, arch),
        [path] if !path.starts_with('-') => cmd_pretty(path),
        _ => {
            eprintln!("usage: honeyc [--tokens|--asm] <file.hny> [--arch aarch64|x86_64]");
            eprintln!("       honeyc check <file.hny>");
            eprintln!("       honeyc build <file.hny> -o <out> [--arch aarch64|x86_64]");
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

fn cmd_check(path: &str) -> i32 {
    let src = read(path);
    let program = match honeyc::parser::parse(&src) {
        Ok(p) => p,
        Err(e) => {
            report(path, &src, e.span().start, &e.message());
            return 1;
        }
    };
    match honeyc::typeck::check(&program) {
        Ok(ok) => {
            eprintln!("{path}: ok ({} bytes of stack)", ok.stack_bytes);
            0
        }
        Err(diags) => {
            report_diags(path, &src, &diags);
            1
        }
    }
}

fn cmd_asm(path: &str, arch: Arch) -> i32 {
    let src = read(path);
    match compile(path, &src, arch) {
        Some(c) => {
            for (i, p) in c.programs.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                println!("; {} ({} bytes stack)", p.name, p.stack_bytes);
                print!("{}", bpf::disasm_prog(&decode_all(&p.bytecode)));
            }
            0
        }
        None => 1,
    }
}

fn cmd_build(path: &str, out: &str, arch: Arch) -> i32 {
    let src = read(path);
    let Some(c) = compile(path, &src, arch) else { return 1 };

    // All programs concatenated; the manifest records each one's offset.
    let mut bin_bytes = Vec::new();
    for p in &c.programs {
        bin_bytes.extend_from_slice(&p.bytecode);
    }
    let bin = format!("{out}.bin");
    let json = format!("{out}.json");
    if let Err(e) = fs::write(&bin, &bin_bytes) {
        eprintln!("{bin}: {e}");
        return 1;
    }
    if let Err(e) = fs::write(&json, manifest(&c)) {
        eprintln!("{json}: {e}");
        return 1;
    }
    eprintln!(
        "wrote {bin} ({} program{}, {} instructions, {}) and {json}",
        c.programs.len(),
        if c.programs.len() == 1 { "" } else { "s" },
        bin_bytes.len() / 8,
        c.arch.name()
    );
    0
}

/// Lex, parse, type-check, and run codegen; report errors against the source.
fn compile(path: &str, src: &str, arch: Arch) -> Option<Compiled> {
    let program = match honeyc::parser::parse(src) {
        Ok(p) => p,
        Err(e) => {
            report(path, src, e.span().start, &e.message());
            return None;
        }
    };
    if let Err(diags) = honeyc::typeck::check(&program) {
        report_diags(path, src, &diags);
        return None;
    }
    match codegen::compile(&program, arch) {
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
///
/// Key names are chosen so the loader's simple scan-for-key reader never
/// hits the wrong object: maps use "map", events "event", programs "prog";
/// only event fields use "name". Sections are in the order maps, events,
/// programs so the loader can bound each scan by the next section's key.
fn manifest(c: &Compiled) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"license\": {},\n", jstr(&c.license)));
    s.push_str(&format!("  \"arch\": \"{}\",\n", c.arch.name()));
    s.push_str(&format!("  \"ringbuf_bytes\": {},\n", c.ringbuf_bytes));
    s.push_str(&format!("  \"record_header\": {},\n", codegen::RECORD_HEADER));
    s.push_str(&format!("  \"stack_bytes\": {},\n", c.stack_bytes));

    s.push_str("  \"maps\": [\n");
    for (i, m) in c.maps.iter().enumerate() {
        let kind = match m.kind { MapKind::Hash => "hash", MapKind::Array => "array" };
        let comma = if i + 1 < c.maps.len() { "," } else { "" };
        s.push_str(&format!(
            "    {{ \"index\": {}, \"map\": {}, \"kind\": \"{}\", \"key_size\": {}, \"value_size\": {}, \"max_entries\": {} }}{}\n",
            i + 1, jstr(&m.name), kind, m.key_size, m.value_size, m.max_entries, comma
        ));
    }
    s.push_str("  ],\n");

    s.push_str("  \"events\": [\n");
    for (id, ev) in c.events.iter().enumerate() {
        s.push_str(&format!("    {{ \"id\": {id}, \"event\": {}, \"size\": {}, \"fields\": [\n", jstr(&ev.name), ev.size));
        for (i, f) in ev.fields.iter().enumerate() {
            let (kind, extra) = match &f.kind {
                FieldKind::Uint(w) => ("uint", format!("\"width\": {w}")),
                FieldKind::Sint(w) => ("int", format!("\"width\": {w}")),
                FieldKind::Str(n) => ("str", format!("\"cap\": {n}")),
                FieldKind::Bool => ("bool", "\"width\": 1".to_string()),
            };
            let comma = if i + 1 < ev.fields.len() { "," } else { "" };
            s.push_str(&format!(
                "      {{ \"name\": {}, \"offset\": {}, \"size\": {}, \"kind\": \"{}\", {} }}{}\n",
                jstr(&f.name), f.offset, f.size, kind, extra, comma
            ));
        }
        let comma = if id + 1 < c.events.len() { "," } else { "" };
        s.push_str(&format!("    ] }}{comma}\n"));
    }
    s.push_str("  ],\n");

    s.push_str("  \"programs\": [\n");
    let mut offset = 0usize;
    for (i, p) in c.programs.iter().enumerate() {
        let attach = match &p.kind {
            ProbeKind::Tracepoint { category, name } => format!(
                "\"type\": \"tracepoint\", \"category\": {}, \"tracepoint\": {}",
                jstr(category), jstr(name)
            ),
            ProbeKind::Kprobe { function } => format!("\"type\": \"kprobe\", \"function\": {}", jstr(function)),
            ProbeKind::Kretprobe { function } => format!("\"type\": \"kretprobe\", \"function\": {}", jstr(function)),
        };
        let comma = if i + 1 < c.programs.len() { "," } else { "" };
        s.push_str(&format!(
            "    {{ \"prog\": {}, {attach}, \"offset\": {offset}, \"insns\": {}, \"stack_bytes\": {} }}{comma}\n",
            jstr(&p.name), p.bytecode.len() / 8, p.stack_bytes
        ));
        offset += p.bytecode.len();
    }
    s.push_str("  ]\n}\n");
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

fn report_diags(path: &str, src: &str, diags: &[honeyc::typeck::Diag]) {
    for d in diags {
        report(path, src, d.span.start, &d.message);
        if let Some(h) = &d.help {
            eprintln!("    help: {h}");
        }
    }
    eprintln!("{path}: {} error{}", diags.len(), if diags.len() == 1 { "" } else { "s" });
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
