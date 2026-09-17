//! `honeyc <file.hny>` — for now, prints the token stream. Grows a stage at a
//! time: tokens → AST → typed AST → bytecode.

use std::{env, fs, process};

fn main() {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: honeyc <file.hny>");
        process::exit(2);
    };

    let src = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{path}: {e}");
            process::exit(1);
        }
    };

    match honeyc::lexer::lex(&src) {
        Ok(tokens) => {
            for t in tokens {
                println!("{:>4}..{:<4} {:?}", t.span.start, t.span.end, t.kind);
            }
        }
        Err(e) => {
            eprintln!("{path}: lex error at bytes {}..{}: {:?}", e.span.start, e.span.end, e.kind);
            process::exit(1);
        }
    }
}
