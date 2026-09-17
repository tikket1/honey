//! honeyc command line.
//!
//!   honeyc <file.hny>            parse and pretty-print the program
//!   honeyc --tokens <file.hny>   dump the token stream

use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (want_tokens, path) = match args.as_slice() {
        [flag, path] if flag == "--tokens" => (true, path),
        [path] => (false, path),
        _ => {
            eprintln!("usage: honeyc [--tokens] <file.hny>");
            process::exit(2);
        }
    };

    let src = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{path}: {e}");
            process::exit(1);
        }
    };

    if want_tokens {
        match honeyc::lexer::lex(&src) {
            Ok(tokens) => {
                for t in tokens {
                    println!("{:>4}..{:<4} {:?}", t.span.start, t.span.end, t.kind);
                }
            }
            Err(e) => {
                report(path, &src, e.span.start, &format!("{:?}", e.kind));
                process::exit(1);
            }
        }
        return;
    }

    match honeyc::parser::parse(&src) {
        Ok(program) => print!("{}", honeyc::pretty::program(&program)),
        Err(e) => {
            report(path, &src, e.span().start, &e.message());
            process::exit(1);
        }
    }
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
    eprintln!("    {}^", " ".repeat(col - 1));
}
