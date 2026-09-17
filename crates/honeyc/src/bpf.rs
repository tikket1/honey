//! eBPF instruction encoding and disassembly.
//!
//! An eBPF program is a flat array of 64-bit instructions. Each instruction
//! is 8 bytes:
//!
//! ```text
//!   byte 0      byte 1        bytes 2-3       bytes 4-7
//!   ┌────────┐  ┌────┬────┐   ┌───────────┐   ┌──────────────┐
//!   │ opcode │  │src │dst │   │  offset   │   │  immediate   │
//!   └────────┘  └────┴────┘   └───────────┘   └──────────────┘
//!     u8         4b   4b        i16 (LE)         i32 (LE)
//! ```
//!
//! The register byte packs two 4-bit register numbers: destination in the
//! low nibble, source in the high nibble. Everything is little-endian, which
//! is the only byte order eBPF targets.
//!
//! One instruction is wider: loading a 64-bit immediate (`LD_IMM64`) takes
//! two slots, 16 bytes. The high 32 bits live in the `imm` field of a second,
//! otherwise-zero instruction. We model that as a single `Insn` and emit two
//! slots for it in [`Insn::encode`].
//!
//! This module knows nothing about honey. It is a faithful assembler for the
//! machine, and the kernel verifier is the thing that ultimately judges
//! whether a sequence we built is legal. Reference: Linux
//! `Documentation/bpf/instruction-set.rst`.

// ---------------------------------------------------------------- registers

/// The eleven eBPF registers. `R0` holds return values and helper results;
/// `R1`–`R5` pass arguments to helpers; `R6`–`R9` are callee-saved (a helper
/// call preserves them); `R10` is the read-only frame pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10,
}

impl Reg {
    fn num(self) -> u8 {
        self as u8
    }
}

// --------------------------------------------------------------- opcode bits

// Instruction classes (low 3 bits of the opcode).
const LD: u8 = 0x00;
const LDX: u8 = 0x01;
const ST: u8 = 0x02;
const STX: u8 = 0x03;
const ALU: u8 = 0x04;
const JMP: u8 = 0x05;
const ALU64: u8 = 0x07;

// Operand source (bit 3): immediate or register.
const K: u8 = 0x00; // use the imm field
const X: u8 = 0x08; // use the src register

// ALU / JMP operations (high 4 bits).
const ADD: u8 = 0x00;
const SUB: u8 = 0x10;
const MUL: u8 = 0x20;
const DIV: u8 = 0x30;
const OR: u8 = 0x40;
const AND: u8 = 0x50;
const LSH: u8 = 0x60;
const RSH: u8 = 0x70;
const NEG: u8 = 0x80;
const MOD: u8 = 0x90;
const XOR: u8 = 0xa0;
const MOV: u8 = 0xb0;
const ARSH: u8 = 0xc0;
const END: u8 = 0xd0;
/// `BPF_TO_BE`: with `END`, convert between host and big-endian byte order.
const TO_BE: u8 = 0x08;

const JA: u8 = 0x00;
const JEQ: u8 = 0x10;
const JGT: u8 = 0x20;
const JGE: u8 = 0x30;
const JSET: u8 = 0x40;
const JNE: u8 = 0x50;
const JLT: u8 = 0xa0;
const JLE: u8 = 0xb0;
const JSGT: u8 = 0x60;
const JSGE: u8 = 0x70;
const JSLT: u8 = 0xc0;
const JSLE: u8 = 0xd0;
const CALL: u8 = 0x80;
const EXIT: u8 = 0x90;

// Memory access size (bits 3-4 of LD/ST opcodes).
const W: u8 = 0x00; // u32
const H: u8 = 0x08; // u16
const B: u8 = 0x10; // u8
const DW: u8 = 0x18; // u64

// Memory access mode.
const MEM: u8 = 0x60;
const IMM: u8 = 0x00;

/// `src_reg = 1` on an `LD_IMM64` means "the immediate is a map file
/// descriptor", asking the loader to relocate it into a real map address.
const PSEUDO_MAP_FD: u8 = 1;

// ----------------------------------------------------------- helper numbers

/// eBPF helper function ids, as the kernel numbers them. Passed as the `imm`
/// of a `call` instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Helper {
    MapLookupElem = 1,
    MapUpdateElem = 2,
    MapDeleteElem = 3,
    KtimeGetNs = 5,
    GetCurrentPidTgid = 14,
    GetCurrentUidGid = 15,
    GetCurrentComm = 16,
    ProbeReadKernel = 113,
    ProbeReadUserStr = 114,
    ProbeReadKernelStr = 115,
    RingbufOutput = 130,
    RingbufReserve = 131,
    RingbufSubmit = 132,
    RingbufDiscard = 133,
}

// ----------------------------------------------------------------- the insn

/// One decoded eBPF instruction. `wide` marks an `LD_IMM64`, which encodes to
/// two 8-byte slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub opcode: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
    wide: bool,
    /// The high 32 bits of a 64-bit immediate (only used when `wide`).
    imm_high: i32,
}

impl Insn {
    fn new(opcode: u8, dst: Reg, src: Reg, off: i16, imm: i32) -> Self {
        Insn { opcode, dst: dst.num(), src: src.num(), off, imm, wide: false, imm_high: 0 }
    }

    /// How many 8-byte slots this instruction occupies (1, or 2 for wide).
    pub fn slots(&self) -> usize {
        if self.wide { 2 } else { 1 }
    }

    /// Rebuild an instruction from decoded fields (used by the disassembler
    /// when reading bytecode back). Pass `imm_high` for a wide LD_IMM64.
    pub fn from_parts(opcode: u8, dst: u8, src: u8, off: i16, imm: i32, imm_high: Option<i32>) -> Self {
        Insn {
            opcode,
            dst,
            src,
            off,
            imm,
            wide: imm_high.is_some(),
            imm_high: imm_high.unwrap_or(0),
        }
    }

    /// Append this instruction's raw bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        push_slot(out, self.opcode, self.src, self.dst, self.off, self.imm);
        if self.wide {
            // Second slot: all zero except the high 32 bits of the immediate.
            push_slot(out, 0, 0, 0, 0, self.imm_high);
        }
    }
}

fn push_slot(out: &mut Vec<u8>, opcode: u8, src: u8, dst: u8, off: i16, imm: i32) {
    out.push(opcode);
    out.push((src << 4) | (dst & 0x0f));
    out.extend_from_slice(&off.to_le_bytes());
    out.extend_from_slice(&imm.to_le_bytes());
}

// ------------------------------------------------------- instruction builders
//
// One constructor per instruction shape we use. Names read like assembly.

/// `dst = imm` (64-bit, sign-extended from the 32-bit immediate).
pub fn mov64_imm(dst: Reg, imm: i32) -> Insn {
    Insn::new(ALU64 | MOV | K, dst, Reg::R0, 0, imm)
}

/// `dst = src` (64-bit).
pub fn mov64_reg(dst: Reg, src: Reg) -> Insn {
    Insn::new(ALU64 | MOV | X, dst, src, 0, 0)
}

/// `dst op= imm` for an arithmetic/bitwise op, 64-bit.
pub fn alu64_imm(op: AluOp, dst: Reg, imm: i32) -> Insn {
    Insn::new(ALU64 | op.bits() | K, dst, Reg::R0, 0, imm)
}

/// `dst op= src`, 64-bit.
pub fn alu64_reg(op: AluOp, dst: Reg, src: Reg) -> Insn {
    Insn::new(ALU64 | op.bits() | X, dst, src, 0, 0)
}

/// `dst op= imm`, 32-bit (the upper half of `dst` is zeroed).
pub fn alu32_imm(op: AluOp, dst: Reg, imm: i32) -> Insn {
    Insn::new(ALU | op.bits() | K, dst, Reg::R0, 0, imm)
}

/// `dst op= src`, 32-bit. `mov32 r, r` is the idiom for zero-extending a
/// register to its low 32 bits.
pub fn alu32_reg(op: AluOp, dst: Reg, src: Reg) -> Insn {
    Insn::new(ALU | op.bits() | X, dst, src, 0, 0)
}

/// `dst = bswap(dst)` for 16 or 32 bits: converts a big-endian (network
/// order) value to host order on little-endian hosts, which is every host
/// eBPF runs on in practice. Encoded as `ALU | END | TO_BE` with the width in
/// `imm`; the kernel defines it as "to big-endian", which on LE is a swap.
pub fn bswap(dst: Reg, bits: u8) -> Insn {
    Insn::new(ALU | END | TO_BE, dst, Reg::R0, 0, bits as i32)
}

/// `dst = imm` as a full 64-bit load (the only way to get a value wider than
/// 32 bits, or a map fd, into a register).
pub fn ld_imm64(dst: Reg, imm: i64) -> Insn {
    let mut insn = Insn::new(LD | DW | IMM, dst, Reg::R0, 0, imm as i32);
    insn.wide = true;
    insn.imm_high = (imm >> 32) as i32;
    insn
}

/// `dst = map_fd`, relocated by the loader into the map's address.
pub fn ld_map_fd(dst: Reg, fd: i32) -> Insn {
    let mut insn = Insn::new(LD | DW | IMM, dst, Reg::R0, 0, fd);
    insn.src = PSEUDO_MAP_FD;
    insn.wide = true;
    insn
}

/// `dst = *(size *)(src + off)` — load from memory.
pub fn ldx_mem(size: Size, dst: Reg, src: Reg, off: i16) -> Insn {
    Insn::new(LDX | size.bits() | MEM, dst, src, off, 0)
}

/// `*(size *)(dst + off) = src` — store a register to memory.
pub fn stx_mem(size: Size, dst: Reg, off: i16, src: Reg) -> Insn {
    Insn::new(STX | size.bits() | MEM, dst, src, off, 0)
}

/// `*(size *)(dst + off) = imm` — store an immediate to memory.
pub fn st_mem(size: Size, dst: Reg, off: i16, imm: i32) -> Insn {
    Insn::new(ST | size.bits() | MEM, dst, Reg::R0, off, imm)
}

/// `if dst op imm goto pc + off` — conditional jump on an immediate.
pub fn jmp_imm(op: JmpOp, dst: Reg, imm: i32, off: i16) -> Insn {
    Insn::new(JMP | op.bits() | K, dst, Reg::R0, off, imm)
}

/// `if dst op src goto pc + off` — conditional jump on a register.
pub fn jmp_reg(op: JmpOp, dst: Reg, src: Reg, off: i16) -> Insn {
    Insn::new(JMP | op.bits() | X, dst, src, off, 0)
}

/// `goto pc + off` — unconditional jump.
pub fn ja(off: i16) -> Insn {
    Insn::new(JMP | JA, Reg::R0, Reg::R0, off, 0)
}

/// `call helper` — invoke a kernel helper; result lands in R0.
pub fn call(helper: Helper) -> Insn {
    Insn::new(JMP | CALL, Reg::R0, Reg::R0, 0, helper as i32)
}

/// `exit` — return R0 to the caller and end the program.
pub fn exit() -> Insn {
    Insn::new(JMP | EXIT, Reg::R0, Reg::R0, 0, 0)
}

// --------------------------------------------------------------- op sub-enums

/// Arithmetic and bitwise operations for `alu*` builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    Add, Sub, Mul, Div, Or, And, Lsh, Rsh, Mod, Xor, Arsh, Neg, Mov,
}

impl AluOp {
    fn bits(self) -> u8 {
        match self {
            AluOp::Add => ADD,
            AluOp::Sub => SUB,
            AluOp::Mul => MUL,
            AluOp::Div => DIV,
            AluOp::Or => OR,
            AluOp::And => AND,
            AluOp::Lsh => LSH,
            AluOp::Rsh => RSH,
            AluOp::Mod => MOD,
            AluOp::Xor => XOR,
            AluOp::Arsh => ARSH,
            AluOp::Neg => NEG,
            AluOp::Mov => MOV,
        }
    }
}

/// Comparisons for the `jmp_*` builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JmpOp {
    Eq, Ne, Gt, Ge, Lt, Le, Set,
    /// Signed comparisons (two's-complement interpretation of the operands).
    Sgt, Sge, Slt, Sle,
}

impl JmpOp {
    fn bits(self) -> u8 {
        match self {
            JmpOp::Eq => JEQ,
            JmpOp::Ne => JNE,
            JmpOp::Gt => JGT,
            JmpOp::Ge => JGE,
            JmpOp::Lt => JLT,
            JmpOp::Le => JLE,
            JmpOp::Set => JSET,
            JmpOp::Sgt => JSGT,
            JmpOp::Sge => JSGE,
            JmpOp::Slt => JSLT,
            JmpOp::Sle => JSLE,
        }
    }
}

/// Memory access widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    B, H, W, DW,
}

impl Size {
    fn bits(self) -> u8 {
        match self {
            Size::B => B,
            Size::H => H,
            Size::W => W,
            Size::DW => DW,
        }
    }
}

// ------------------------------------------------------------------- program

/// A growable instruction list with jump-patching by label. You emit
/// instructions, drop [`Prog::label`] markers, and reference them in jumps;
/// [`Prog::encode`] resolves every label to a real offset.
#[derive(Debug, Default)]
pub struct Prog {
    insns: Vec<Insn>,
    /// (index of the jump instruction, label it targets).
    fixups: Vec<(usize, u32)>,
    /// label id -> instruction index it points at.
    labels: Vec<Option<usize>>,
}

/// A jump target. Create with [`Prog::new_label`], place with
/// [`Prog::bind`], jump to it with the `*_to` methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label(u32);

impl Prog {
    pub fn new() -> Self {
        Prog::default()
    }

    /// Append a fully-formed instruction.
    pub fn push(&mut self, insn: Insn) -> &mut Self {
        self.insns.push(insn);
        self
    }

    /// Reserve a new label id (not yet placed).
    pub fn new_label(&mut self) -> Label {
        self.labels.push(None);
        Label((self.labels.len() - 1) as u32)
    }

    /// Bind a label to the current position (the next instruction emitted).
    pub fn bind(&mut self, label: Label) {
        self.labels[label.0 as usize] = Some(self.insns.len());
    }

    /// `if dst op imm goto label`.
    pub fn jmp_imm_to(&mut self, op: JmpOp, dst: Reg, imm: i32, label: Label) -> &mut Self {
        self.fixups.push((self.insns.len(), label.0));
        self.insns.push(jmp_imm(op, dst, imm, 0));
        self
    }

    /// `if dst op src goto label`.
    pub fn jmp_reg_to(&mut self, op: JmpOp, dst: Reg, src: Reg, label: Label) -> &mut Self {
        self.fixups.push((self.insns.len(), label.0));
        self.insns.push(jmp_reg(op, dst, src, 0));
        self
    }

    /// `goto label`.
    pub fn ja_to(&mut self, label: Label) -> &mut Self {
        self.fixups.push((self.insns.len(), label.0));
        self.insns.push(ja(0));
        self
    }

    /// Number of instructions (LD_IMM64 counts as one here).
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Resolve labels and return the instruction list, or an error naming a
    /// label that was referenced but never bound.
    pub fn resolve(mut self) -> Result<Vec<Insn>, String> {
        // A jump offset is measured in slots, relative to the instruction
        // *after* the jump. We need slot indices, so first map each
        // instruction index to its starting slot.
        let mut slot_of = Vec::with_capacity(self.insns.len() + 1);
        let mut slot = 0usize;
        for insn in &self.insns {
            slot_of.push(slot);
            slot += insn.slots();
        }
        slot_of.push(slot); // one past the end

        for &(at, label) in &self.fixups {
            let target = self.labels[label as usize]
                .ok_or_else(|| format!("label {label} used but never bound"))?;
            // offset = target_slot - (slot after this jump)
            let from = slot_of[at] + 1;
            let to = slot_of[target];
            let off = to as isize - from as isize;
            self.insns[at].off = i16::try_from(off)
                .map_err(|_| format!("jump offset {off} out of range for i16"))?;
        }
        Ok(self.insns)
    }

    /// Convenience: resolve and flatten to raw bytes.
    pub fn to_bytes(self) -> Result<Vec<u8>, String> {
        let insns = self.resolve()?;
        let mut out = Vec::with_capacity(insns.len() * 8);
        for insn in &insns {
            insn.encode(&mut out);
        }
        Ok(out)
    }
}

// --------------------------------------------------------------- disassembler

/// Render one instruction as human-readable assembly, roughly matching
/// `llvm-objdump`'s eBPF syntax. Used by tests and `honeyc --asm`.
pub fn disasm(insn: &Insn) -> String {
    let class = insn.opcode & 0x07;
    let dst = format!("r{}", insn.dst);
    let src = format!("r{}", insn.src);
    match class {
        ALU | ALU64 => {
            let suffix = if class == ALU { "32" } else { "" };
            let op = insn.opcode & 0xf0;
            if op == END {
                return format!("bswap{} {dst}", insn.imm);
            }
            let name = alu_name(op);
            if op == NEG {
                return format!("{name}{suffix} {dst}");
            }
            if insn.opcode & X != 0 {
                format!("{name}{suffix} {dst}, {src}")
            } else {
                format!("{name}{suffix} {dst}, {}", insn.imm)
            }
        }
        LD if insn.opcode == (LD | DW | IMM) => {
            if insn.src == PSEUDO_MAP_FD {
                format!("ld64 {dst}, map_fd({})", insn.imm)
            } else {
                let full = ((insn.imm_high as i64) << 32) | (insn.imm as u32 as i64);
                format!("ld64 {dst}, {full}")
            }
        }
        LDX => {
            let sz = size_name(insn.opcode);
            format!("ldx{sz} {dst}, [{src} {:+}]", insn.off)
        }
        ST => {
            let sz = size_name(insn.opcode);
            format!("st{sz} [{dst} {:+}], {}", insn.off, insn.imm)
        }
        STX => {
            let sz = size_name(insn.opcode);
            format!("stx{sz} [{dst} {:+}], {src}", insn.off)
        }
        JMP => {
            let op = insn.opcode & 0xf0;
            match op {
                EXIT => "exit".to_string(),
                CALL => format!("call {}", insn.imm),
                JA => format!("goto {:+}", insn.off),
                _ => {
                    let name = jmp_name(op);
                    if insn.opcode & X != 0 {
                        format!("if {dst} {name} {src} goto {:+}", insn.off)
                    } else {
                        format!("if {dst} {name} {} goto {:+}", insn.imm, insn.off)
                    }
                }
            }
        }
        _ => format!("<unknown opcode {:#04x}>", insn.opcode),
    }
}

/// Disassemble a whole program, one instruction per line with slot numbers.
pub fn disasm_prog(insns: &[Insn]) -> String {
    let mut out = String::new();
    let mut slot = 0;
    for insn in insns {
        out.push_str(&format!("{slot:4}: {}\n", disasm(insn)));
        slot += insn.slots();
    }
    out
}

fn alu_name(op: u8) -> &'static str {
    match op {
        ADD => "add", SUB => "sub", MUL => "mul", DIV => "div", OR => "or",
        AND => "and", LSH => "lsh", RSH => "rsh", NEG => "neg", MOD => "mod",
        XOR => "xor", MOV => "mov", ARSH => "arsh", _ => "alu?",
    }
}

fn jmp_name(op: u8) -> &'static str {
    match op {
        JEQ => "==", JNE => "!=", JGT => ">", JGE => ">=", JLT => "<",
        JLE => "<=", JSET => "&", JSGT => "s>", JSGE => "s>=", JSLT => "s<",
        JSLE => "s<=", _ => "jmp?",
    }
}

fn size_name(opcode: u8) -> &'static str {
    match opcode & 0x18 {
        B => "8", H => "16", W => "32", DW => "64", _ => "?",
    }
}

// ------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(insn: Insn) -> Vec<u8> {
        let mut v = Vec::new();
        insn.encode(&mut v);
        v
    }

    #[test]
    fn mov64_imm_encoding() {
        // mov r1, 24  ->  b7 01 00 00 18 00 00 00
        assert_eq!(bytes(mov64_imm(Reg::R1, 24)), [0xb7, 0x01, 0, 0, 0x18, 0, 0, 0]);
    }

    #[test]
    fn mov64_reg_encoding() {
        // mov r6, r0  ->  bf 06 00 00 00 00 00 00
        assert_eq!(bytes(mov64_reg(Reg::R6, Reg::R0)), [0xbf, 0x06, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn reg_byte_packs_src_high_dst_low() {
        // mov r3, r5  ->  reg byte = (5<<4)|3 = 0x53
        assert_eq!(bytes(mov64_reg(Reg::R3, Reg::R5))[1], 0x53);
    }

    #[test]
    fn exit_encoding() {
        assert_eq!(bytes(exit()), [0x95, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn call_encoding() {
        // call bpf_get_current_pid_tgid (14) -> 85 00 00 00 0e 00 00 00
        assert_eq!(bytes(call(Helper::GetCurrentPidTgid)), [0x85, 0, 0, 0, 0x0e, 0, 0, 0]);
    }

    #[test]
    fn alu64_rsh_imm_encoding() {
        // rsh r0, 32 -> 77 00 00 00 20 00 00 00
        assert_eq!(bytes(alu64_imm(AluOp::Rsh, Reg::R0, 32)), [0x77, 0, 0, 0, 0x20, 0, 0, 0]);
    }

    #[test]
    fn alu64_add_imm_encoding() {
        // add r1, 8 -> 07 01 00 00 08 00 00 00
        assert_eq!(bytes(alu64_imm(AluOp::Add, Reg::R1, 8)), [0x07, 0x01, 0, 0, 0x08, 0, 0, 0]);
    }

    #[test]
    fn stx_word_encoding() {
        // stxw [r6+0], r0 -> 63 06 00 00 00 00 00 00
        assert_eq!(bytes(stx_mem(Size::W, Reg::R6, 0, Reg::R0)), [0x63, 0x06, 0, 0, 0, 0, 0, 0]);
        // offset is little-endian in bytes 2-3
        assert_eq!(bytes(stx_mem(Size::W, Reg::R6, 4, Reg::R0))[2..4], [0x04, 0x00]);
    }

    #[test]
    fn ldx_dw_negative_offset_is_sign_extended() {
        // ldxdw r2, [r10-8] -> off = -8 = 0xfff8 LE
        let v = bytes(ldx_mem(Size::DW, Reg::R2, Reg::R10, -8));
        assert_eq!(v[0], 0x79); // LDX|DW|MEM
        assert_eq!(&v[2..4], &[0xf8, 0xff]);
    }

    #[test]
    fn ld_imm64_is_two_slots() {
        // ld64 r1, 0x1_0000_0002
        let insn = ld_imm64(Reg::R1, 0x1_0000_0002);
        assert_eq!(insn.slots(), 2);
        let v = bytes(insn);
        assert_eq!(v.len(), 16);
        assert_eq!(v[0], 0x18); // LD|DW|IMM
        assert_eq!(&v[4..8], &2i32.to_le_bytes()); // low 32
        assert_eq!(&v[8..12], &[0, 0, 0, 0]); // second slot opcode zero
        assert_eq!(&v[12..16], &1i32.to_le_bytes()); // high 32
    }

    #[test]
    fn ld_map_fd_sets_pseudo_source() {
        // ld64 r1, map_fd(7) -> src reg nibble = 1 (PSEUDO_MAP_FD)
        let v = bytes(ld_map_fd(Reg::R1, 7));
        assert_eq!(v.len(), 16);
        assert_eq!(v[0], 0x18);
        assert_eq!(v[1] >> 4, PSEUDO_MAP_FD);
        assert_eq!(&v[4..8], &7i32.to_le_bytes());
    }

    #[test]
    fn forward_jump_offset_counts_slots_after_the_jump() {
        // jump over a single mov, landing on exit:
        //   0: if r0 == 0 goto +1
        //   1: mov r0, 1
        //   2: exit
        let mut p = Prog::new();
        let end = p.new_label();
        p.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, end);
        p.push(mov64_imm(Reg::R0, 1));
        p.bind(end);
        p.push(exit());
        let insns = p.resolve().unwrap();
        assert_eq!(insns[0].off, 1);
    }

    #[test]
    fn jump_offset_accounts_for_wide_instructions() {
        // A wide LD_IMM64 between the jump and its target counts as 2 slots.
        //   slot 0: if r0 == 0 goto target
        //   slot 1-2: ld64 r1, big
        //   slot 3: target -> exit
        let mut p = Prog::new();
        let target = p.new_label();
        p.jmp_imm_to(JmpOp::Eq, Reg::R0, 0, target);
        p.push(ld_imm64(Reg::R1, 0x1_0000_0000));
        p.bind(target);
        p.push(exit());
        let insns = p.resolve().unwrap();
        // from = slot 0 + 1 = 1; to = slot 3; off = 2
        assert_eq!(insns[0].off, 2);
    }

    #[test]
    fn backward_jump_is_negative() {
        //   0: mov r0, 0
        //   1: goto -2   (back to slot 0)
        let mut p = Prog::new();
        let top = p.new_label();
        p.bind(top);
        p.push(mov64_imm(Reg::R0, 0));
        p.ja_to(top);
        let insns = p.resolve().unwrap();
        // from = 1 + 1 = 2; to = 0; off = -2
        assert_eq!(insns[1].off, -2);
    }

    #[test]
    fn unbound_label_is_an_error() {
        let mut p = Prog::new();
        let l = p.new_label();
        p.ja_to(l);
        assert!(p.resolve().is_err());
    }

    #[test]
    fn disasm_reads_back_key_instructions() {
        assert_eq!(disasm(&mov64_imm(Reg::R1, 24)), "mov r1, 24");
        assert_eq!(disasm(&mov64_reg(Reg::R6, Reg::R0)), "mov r6, r0");
        assert_eq!(disasm(&exit()), "exit");
        assert_eq!(disasm(&call(Helper::RingbufSubmit)), "call 132");
        assert_eq!(disasm(&alu64_imm(AluOp::Rsh, Reg::R0, 32)), "rsh r0, 32");
        assert_eq!(disasm(&stx_mem(Size::W, Reg::R6, 4, Reg::R0)), "stx32 [r6 +4], r0");
        assert_eq!(disasm(&ld_map_fd(Reg::R1, 0)), "ld64 r1, map_fd(0)");
        assert_eq!(disasm(&jmp_imm(JmpOp::Eq, Reg::R0, 0, 3)), "if r0 == 0 goto +3");
    }
}
