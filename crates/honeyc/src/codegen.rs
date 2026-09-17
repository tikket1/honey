//! Stage 3 codegen (first slice): compile a detection probe to BPF bytecode.
//!
//! WHAT IS SUPPORTED RIGHT NOW: a program with one or more `event`
//! declarations and exactly one `probe` whose body is a single `emit` of an
//! event. Each emitted field's value must be a call to a nullary builtin
//! (`pid()`, `tgid()`, `uid()`, `gid()`, `ktime()`) or `comm()`. That is
//! exactly `examples/exec.hny`, and it is enough to drive a full vertical
//! slice: source → bytecode → loaded into the kernel → firing on execve.
//!
//! NOT YET: maps, `if`/`for`, arithmetic, string matching, `const`. Those are
//! stage 3b; codegen returns a clear "not yet supported" error for them
//! rather than emitting something the verifier would reject. Extending this
//! is the next chunk of work, and the structure here (one ring-buffer record,
//! reserve/fill/submit) is the skeleton the rest hangs off.
//!
//! The record is built in the ring buffer: reserve space, write each field,
//! submit. See `layout.rs` for how the record's bytes are arranged.

use crate::ast::{Expr, ExprKind, Item, Program, StmtKind};
use crate::bpf::*;
use crate::layout::{layout_event, EventLayout, FieldKind};

/// A compiled probe plus everything the loader needs to install it.
#[derive(Debug, Clone)]
pub struct Compiled {
    pub bytecode: Vec<u8>,
    /// `("syscalls", "sys_enter_execve")`.
    pub tracepoint: (String, String),
    /// The one ring-buffer map this program writes to.
    pub ringbuf_bytes: u32,
    /// Layout of the record the loader will read back.
    pub event: EventLayout,
    pub license: String,
}

const RINGBUF_MAP_INDEX: i32 = 0;

pub fn compile(program: &Program) -> Result<Compiled, String> {
    // Collect events and the single probe.
    let mut events = Vec::new();
    let mut probe = None;
    for item in &program.items {
        match item {
            Item::Event(e) => events.push(e),
            Item::Probe(p) => {
                if probe.is_some() {
                    return Err("this codegen slice supports only one probe".into());
                }
                probe = Some(p);
            }
            Item::Const(_) => return Err("`const` is not supported yet (stage 3b)".into()),
            Item::Map(_) => return Err("`map` is not supported yet (stage 3b)".into()),
        }
    }
    let probe = probe.ok_or("no probe to compile")?;

    // Attach point: probe tracepoint("cat", "name").
    if probe.kind.name != "tracepoint" {
        return Err(format!("only `tracepoint` probes are supported yet, got `{}`", probe.kind.name));
    }
    let [category, name] = probe.args.as_slice() else {
        return Err("tracepoint probe needs exactly two string arguments".into());
    };

    // Body must be a single `emit E { ... }`.
    let [stmt] = probe.body.stmts.as_slice() else {
        return Err("this codegen slice supports a probe body of exactly one `emit`".into());
    };
    let StmtKind::Emit { event: event_name, fields } = &stmt.kind else {
        return Err("this codegen slice supports only an `emit` statement in the probe body".into());
    };

    let event_decl = events
        .iter()
        .find(|e| e.name.name == event_name.name)
        .ok_or_else(|| format!("unknown event `{}`", event_name.name))?;
    let layout = layout_event(event_decl)?;

    // Every declared field must be assigned exactly once.
    if fields.len() != layout.fields.len() {
        return Err(format!(
            "event `{}` has {} fields but `emit` provides {}",
            layout.name, layout.fields.len(), fields.len()
        ));
    }

    let mut prog = Prog::new();
    let drop = prog.new_label();

    // r0 = bpf_ringbuf_reserve(&ringbuf, size, 0)
    prog.push(ld_map_fd(Reg::R1, RINGBUF_MAP_INDEX));
    prog.push(mov64_imm(Reg::R2, layout.size as i32));
    prog.push(mov64_imm(Reg::R3, 0));
    prog.push(call(Helper::RingbufReserve));
    // if r0 == 0 goto drop  (reservation failed: nothing to do)
    prog.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, drop);
    // r6 = r0  (r6 is callee-saved, survives helper calls)
    prog.push(mov64_reg(Reg::R6, Reg::R0));

    // Fill each field. Match emit fields to the declared layout by name.
    for (fname, value) in fields {
        let fl = layout
            .fields
            .iter()
            .find(|f| f.name == fname.name)
            .ok_or_else(|| format!("event `{}` has no field `{}`", layout.name, fname.name))?;
        emit_field(&mut prog, fl.offset, &fl.kind, value)?;
    }

    // bpf_ringbuf_submit(r6, 0)
    prog.push(mov64_reg(Reg::R1, Reg::R6));
    prog.push(mov64_imm(Reg::R2, 0));
    prog.push(call(Helper::RingbufSubmit));

    // drop: return 0
    prog.bind(drop);
    prog.push(mov64_imm(Reg::R0, 0));
    prog.push(exit());

    let bytecode = prog.to_bytes()?;

    Ok(Compiled {
        bytecode,
        tracepoint: (category.clone(), name.clone()),
        ringbuf_bytes: 1 << 16, // 64 KiB, a page-multiple power of two
        event: layout,
        license: "GPL".into(),
    })
}

/// Emit the instructions that write one field of the record at `[r6 + off]`.
fn emit_field(prog: &mut Prog, off: u32, kind: &FieldKind, value: &Expr) -> Result<(), String> {
    let off = i16::try_from(off).map_err(|_| "field offset too large".to_string())?;

    match &value.kind {
        // A nullary builtin: pid(), uid(), ktime(), ...
        ExprKind::Call { callee, args } if args.is_empty() => {
            let name = ident_name(callee)?;
            emit_builtin(prog, off, kind, &name)
        }
        // comm() is special: it writes into the record rather than returning.
        _ => Err(format!(
            "unsupported field value; this slice only accepts nullary builtins, got `{}`",
            crate::pretty::expr(value)
        )),
    }
}

fn emit_builtin(prog: &mut Prog, off: i16, kind: &FieldKind, name: &str) -> Result<(), String> {
    match name {
        "pid" | "tgid" => {
            // bpf_get_current_pid_tgid() = (tgid << 32) | pid.
            // pid()  -> userspace PID = tgid = high 32 bits.
            // tgid() -> same value (alias for clarity).
            expect_uint(kind, name, 4)?;
            prog.push(call(Helper::GetCurrentPidTgid));
            prog.push(alu64_imm(AluOp::Rsh, Reg::R0, 32));
            prog.push(stx_mem(Size::W, Reg::R6, off, Reg::R0));
            Ok(())
        }
        "uid" | "gid" => {
            // bpf_get_current_uid_gid() = (gid << 32) | uid.
            expect_uint(kind, name, 4)?;
            prog.push(call(Helper::GetCurrentUidGid));
            if name == "gid" {
                prog.push(alu64_imm(AluOp::Rsh, Reg::R0, 32));
            }
            // storing W truncates to the low 32 bits (uid)
            prog.push(stx_mem(Size::W, Reg::R6, off, Reg::R0));
            Ok(())
        }
        "ktime" => {
            expect_uint(kind, name, 8)?;
            prog.push(call(Helper::KtimeGetNs));
            prog.push(stx_mem(Size::DW, Reg::R6, off, Reg::R0));
            Ok(())
        }
        "comm" => {
            // bpf_get_current_comm(&record[off], N) fills the field in place.
            let FieldKind::Str(n) = kind else {
                return Err(format!("`comm()` must fill a `str<N>` field, not {kind:?}"));
            };
            prog.push(mov64_reg(Reg::R1, Reg::R6));
            prog.push(alu64_imm(AluOp::Add, Reg::R1, off as i32));
            prog.push(mov64_imm(Reg::R2, *n as i32));
            prog.push(call(Helper::GetCurrentComm));
            Ok(())
        }
        other => Err(format!("unknown builtin `{other}()`")),
    }
}

fn expect_uint(kind: &FieldKind, builtin: &str, width: u32) -> Result<(), String> {
    match kind {
        FieldKind::Uint(w) if *w == width => Ok(()),
        _ => Err(format!("`{builtin}()` produces a u{}, field is {kind:?}", width * 8)),
    }
}

fn ident_name(e: &Expr) -> Result<String, String> {
    match &e.kind {
        ExprKind::Ident(name) => Ok(name.clone()),
        _ => Err("expected a builtin name".into()),
    }
}
