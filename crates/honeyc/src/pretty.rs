//! Print an AST back out as honey source. Two uses:
//!
//! 1. Debugging: `honeyc file.hny` shows what the parser understood.
//! 2. Testing: parse → print → parse → print must be a fixed point, and
//!    every compound expression is printed fully parenthesised so a test can
//!    check precedence by string comparison: `1 + 2 * 3` prints as
//!    `(1 + (2 * 3))`.

use crate::ast::*;
use std::fmt::Write;

pub fn program(p: &Program) -> String {
    let mut out = String::new();
    for (i, item) in p.items.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        write_item(&mut out, item);
    }
    out
}

pub fn expr(e: &Expr) -> String {
    let mut out = String::new();
    write_expr(&mut out, e);
    out
}

pub fn ty(t: &Type) -> String {
    let mut out = String::new();
    write_type(&mut out, t);
    out
}

fn write_item(out: &mut String, item: &Item) {
    match item {
        Item::Const(c) => {
            let _ = write!(out, "const {}: ", c.name.name);
            write_type(out, &c.ty);
            out.push_str(" = ");
            write_expr(out, &c.value);
            out.push_str(";\n");
        }
        Item::Map(m) => {
            let _ = write!(out, "map {}: {}<", m.name.name, m.kind.name);
            for (i, a) in m.args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_type(out, a);
            }
            let _ = writeln!(out, ">[{}];", m.capacity);
        }
        Item::Event(e) => {
            let _ = writeln!(out, "event {} {{", e.name.name);
            for f in &e.fields {
                let _ = write!(out, "    {}: ", f.name.name);
                write_type(out, &f.ty);
                out.push_str(",\n");
            }
            out.push_str("}\n");
        }
        Item::Probe(p) => {
            let _ = write!(out, "probe {}(", p.kind.name);
            for (i, a) in p.args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_str_literal(out, a);
            }
            out.push_str(") ");
            write_block(out, &p.body, 0);
            out.push('\n');
        }
    }
}

fn write_type(out: &mut String, t: &Type) {
    out.push_str(&t.name.name);
    if !t.args.is_empty() {
        out.push('<');
        for (i, a) in t.args.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            match a {
                TypeArg::Type(t) => write_type(out, t),
                TypeArg::Int(n) => {
                    let _ = write!(out, "{n}");
                }
            }
        }
        out.push('>');
    }
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("    ");
    }
}

fn write_block(out: &mut String, b: &Block, level: usize) {
    out.push_str("{\n");
    for s in &b.stmts {
        write_stmt(out, s, level + 1);
    }
    indent(out, level);
    out.push('}');
}

fn write_stmt(out: &mut String, s: &Stmt, level: usize) {
    indent(out, level);
    match &s.kind {
        StmtKind::Let { mutable, name, ty, value } => {
            out.push_str("let ");
            if *mutable {
                out.push_str("mut ");
            }
            out.push_str(&name.name);
            if let Some(t) = ty {
                out.push_str(": ");
                write_type(out, t);
            }
            out.push_str(" = ");
            write_expr(out, value);
            out.push_str(";\n");
        }
        StmtKind::Assign { target, value } => {
            write_expr(out, target);
            out.push_str(" = ");
            write_expr(out, value);
            out.push_str(";\n");
        }
        StmtKind::If { cond, then, otherwise } => {
            out.push_str("if ");
            match cond {
                Cond::Expr(e) => write_expr(out, e),
                Cond::Let { pattern, value } => {
                    out.push_str("let ");
                    out.push_str(&pattern.name.name);
                    if let Some(b) = &pattern.binding {
                        let _ = write!(out, "({})", b.name);
                    }
                    out.push_str(" = ");
                    write_expr(out, value);
                }
            }
            out.push(' ');
            write_block(out, then, level);
            if let Some(e) = otherwise {
                out.push_str(" else ");
                write_block(out, e, level);
            }
            out.push('\n');
        }
        StmtKind::For { var, start, end, body } => {
            let _ = write!(out, "for {} in ", var.name);
            write_expr(out, start);
            out.push_str("..");
            write_expr(out, end);
            out.push(' ');
            write_block(out, body, level);
            out.push('\n');
        }
        StmtKind::Emit { event, fields } => {
            let _ = write!(out, "emit {} {{ ", event.name);
            for (i, (name, value)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                let _ = write!(out, "{}: ", name.name);
                write_expr(out, value);
            }
            out.push_str(" };\n");
        }
        StmtKind::Return(value) => {
            out.push_str("return");
            if let Some(v) = value {
                out.push(' ');
                write_expr(out, v);
            }
            out.push_str(";\n");
        }
        StmtKind::Expr(e) => {
            write_expr(out, e);
            out.push_str(";\n");
        }
    }
}

fn write_expr(out: &mut String, e: &Expr) {
    match &e.kind {
        ExprKind::Int(n) => {
            let _ = write!(out, "{n}");
        }
        ExprKind::Str(s) => write_str_literal(out, s),
        ExprKind::Bool(b) => {
            let _ = write!(out, "{b}");
        }
        ExprKind::Ident(name) => out.push_str(name),
        ExprKind::Unary { op, expr } => {
            out.push('(');
            out.push_str(op.symbol());
            write_expr(out, expr);
            out.push(')');
        }
        ExprKind::Binary { op, lhs, rhs } => {
            out.push('(');
            write_expr(out, lhs);
            let _ = write!(out, " {} ", op.symbol());
            write_expr(out, rhs);
            out.push(')');
        }
        ExprKind::Cast { expr, ty } => {
            out.push('(');
            write_expr(out, expr);
            out.push_str(" as ");
            write_type(out, ty);
            out.push(')');
        }
        ExprKind::Call { callee, args } => {
            write_expr(out, callee);
            write_args(out, args);
        }
        ExprKind::MethodCall { receiver, method, args } => {
            write_expr(out, receiver);
            out.push('.');
            out.push_str(&method.name);
            write_args(out, args);
        }
        ExprKind::Field { expr, field } => {
            write_expr(out, expr);
            out.push('.');
            out.push_str(&field.name);
        }
        ExprKind::Index { expr, index } => {
            write_expr(out, expr);
            out.push('[');
            write_expr(out, index);
            out.push(']');
        }
    }
}

fn write_args(out: &mut String, args: &[Expr]) {
    out.push('(');
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        write_expr(out, a);
    }
    out.push(')');
}

/// Re-escape a decoded string so it lexes back to the same value.
fn write_str_literal(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
