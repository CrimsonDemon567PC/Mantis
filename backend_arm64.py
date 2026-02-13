# ============================================================
# Mantis 7 — Native ARM64 Backend
# Single-function MTN → AArch64 machine code (AAPCS64)
# ============================================================

from __future__ import annotations
import struct

# ================= OPCODES (shared ISA) =================

OP_CONST_I64    = 1
OP_CONST_F64    = 2
OP_ADD          = 3
OP_SUB          = 4
OP_MUL          = 5
OP_DIV          = 6
OP_RETURN       = 7
OP_CALL         = 8
OP_LOAD         = 9
OP_STORE        = 10
OP_ALLOC_STACK  = 11
OP_FIELD_LOAD   = 12
OP_FIELD_STORE  = 13
OP_JMP          = 14
OP_JMP_IF_FALSE = 15
OP_CMP_EQ       = 16
OP_CMP_LT       = 17
OP_CMP_GT       = 18


# ============================================================
# ARM64 ENCODING HELPERS
# ============================================================

def _u32(x: int) -> bytes:
    return struct.pack("<I", x)


def _movz(rd: int, imm16: int, shift: int):
    return _u32(0xD2800000 | (shift << 21) | (imm16 << 5) | rd)


def _movk(rd: int, imm16: int, shift: int):
    return _u32(0xF2800000 | (shift << 21) | (imm16 << 5) | rd)


def _mov_imm64(rd: int, val: int) -> bytes:
    """
    Build a 64-bit immediate in rd using MOVZ/MOVK.
    """
    parts = []
    for i in range(4):
        imm = (val >> (i * 16)) & 0xFFFF
        if i == 0:
            parts.append(_movz(rd, imm, i))
        else:
            parts.append(_movk(rd, imm, i))
    return b"".join(parts)


def _add(rd, rn, rm):
    return _u32(0x8B000000 | (rm << 16) | (rn << 5) | rd)


def _sub(rd, rn, rm):
    return _u32(0xCB000000 | (rm << 16) | (rn << 5) | rd)


def _mul(rd, rn, rm):
    return _u32(0x9B007C00 | (rm << 16) | (rn << 5) | rd)


def _sdiv(rd, rn, rm):
    return _u32(0x9AC00C00 | (rm << 16) | (rn << 5) | rd)


def _cmp(rn, rm):
    """
    cmp rn, rm  (alias: subs xzr, rn, rm)
    """
    return _u32(0xEB00001F | (rm << 16) | (rn << 5))


def _cset(rd, cond):
    """
    cset rd, cond
    """
    return _u32(0x9A9F07E0 | (cond << 12) | rd)


def _ldr_stack(rt, offset):
    """
    ldr rt, [fp, #offset]
    fp = x29
    """
    return _u32(0xF9400000 | ((offset // 8) << 10) | (29 << 5) | rt)


def _str_stack(rt, offset):
    """
    str rt, [fp, #offset]
    fp = x29
    """
    return _u32(0xF9000000 | ((offset // 8) << 10) | (29 << 5) | rt)


def _ret():
    return _u32(0xD65F03C0)


def _b(offset):
    """
    Unconditional branch (rel32 >> 2)
    """
    return _u32(0x14000000 | ((offset >> 2) & 0x03FFFFFF))


def _b_cond(offset, cond):
    """
    Conditional branch with condition code.
    """
    return _u32(0x54000000 | (((offset >> 2) & 0x7FFFF) << 5) | cond)


def _bl(offset):
    """
    Branch with link.
    """
    return _u32(0x94000000 | ((offset >> 2) & 0x03FFFFFF))


def _stp_fp_lr():
    """
    stp x29, x30, [sp, #-16]!
    """
    return _u32(0xA9BF7BFD)


def _ldp_fp_lr():
    """
    ldp x29, x30, [sp], #16
    """
    return _u32(0xA8C17BFD)


def _mov_fp_sp():
    """
    mov x29, sp
    """
    return _u32(0x910003FD)


def _sub_sp(size):
    """
    sub sp, sp, #size
    """
    return _u32(0xD10003FF | ((size & 0xFFF) << 10))


def _add_sp(size):
    """
    add sp, sp, #size
    """
    return _u32(0x910003FF | ((size & 0xFFF) << 10))


# -------- FP helpers (D‑registers, d0/d1) --------

def _fmov_d0_x0():
    """
    fmov d0, x0
    """
    return _u32(0x9E660000)


def _fmov_x0_d0():
    """
    fmov x0, d0
    """
    return _u32(0x9E660000 | (0 << 5) | 0)


def _fadd_d0_d0_d1():
    """
    fadd d0, d0, d1
    """
    return _u32(0x1E602800 | (1 << 16) | (0 << 5) | 0)


def _fsub_d0_d0_d1():
    """
    fsub d0, d0, d1
    """
    return _u32(0x1E603800 | (1 << 16) | (0 << 5) | 0)


def _fmul_d0_d0_d1():
    """
    fmul d0, d0, d1
    """
    return _u32(0x1E600800 | (1 << 16) | (0 << 5) | 0)


def _fdiv_d0_d0_d1():
    """
    fdiv d0, d0, d1
    """
    return _u32(0x1E601800 | (1 << 16) | (0 << 5) | 0)


def _fcmp_d0_d1():
    """
    fcmp d0, d1
    """
    return _u32(0x1E602000 | (1 << 16) | (0 << 5))


# ============================================================
# ABI ARGUMENT REGISTERS (AAPCS64)
# x0-x7
# ============================================================

ABI_REGS = list(range(8))

# ============================================================
# MAIN EMITTER
# ============================================================

def emit_arm64(bytecode: bytes) -> bytes:
    """
    Translate a single-function MTN bytecode buffer into AArch64
    machine code using AAPCS64 calling convention.
    - x0 is primary value register
    - x1 is secondary value register
    - d0/d1 werden für F64-Arithmetik genutzt, Ergebnis zurück in x0
    """

    # ---------- parse MTN header ----------
    if bytecode[:4] != b"MTN1":
        raise RuntimeError("Invalid MTN")

    pos = 4
    fn_count = struct.unpack_from("<I", bytecode, pos)[0]
    pos += 4

    # v1: only first function is used
    code_len = struct.unpack_from("<I", bytecode, pos)[0]
    pos += 4

    instrs = []
    for _ in range(code_len):
        op, a, b, c = struct.unpack_from("<Biii", bytecode, pos)
        pos += 13
        instrs.append((op, a, b, c))

    # =========================================================
    # CODEGEN
    # =========================================================

    out = bytearray()

    # ---------- prologue ----------
    out += _stp_fp_lr()
    out += _mov_fp_sp()
    out += _sub_sp(32)  # fixed local space (v1)

    labels = []   # byte offset of each instruction
    fixups = []   # (patch_pos, target_index, kind)
    last_was_float = False  # simple type flag for top-of-stack

    for i, (op, a, b, c) in enumerate(instrs):

        labels.append(len(out))

        # ---------- CONST ----------
        if op == OP_CONST_I64:
            out += _mov_imm64(0, a)
            last_was_float = False

        elif op == OP_CONST_F64:
            # load raw 64-bit payload into x0, mirror into d0
            out += _mov_imm64(0, a)
            out += _fmov_d0_x0()
            last_was_float = True

        # ---------- LOAD / STORE ----------
        elif op == OP_LOAD:
            out += _ldr_stack(0, a)
            last_was_float = False  # v1: stack hält i64/pointer

        elif op == OP_STORE:
            out += _str_stack(0, a)
            # Typflag bleibt unverändert

        # ---------- ARITH ----------
        elif op == OP_ADD:
            if last_was_float:
                # float: d0 = d0 + d1 (x1 → d1), Ergebnis zurück nach x0
                out += _fmov_d0_x0()      # sicherstellen, dass d0 aus x0 kommt
                # x1 wird vom Frontend befüllt; hier nur FP-ALU
                out += _fadd_d0_d0_d1()
                out += _fmov_x0_d0()
            else:
                out += _add(0, 0, 1)

        elif op == OP_SUB:
            if last_was_float:
                out += _fmov_d0_x0()
                out += _fsub_d0_d0_d1()
                out += _fmov_x0_d0()
            else:
                out += _sub(0, 0, 1)

        elif op == OP_MUL:
            if last_was_float:
                out += _fmov_d0_x0()
                out += _fmul_d0_d0_d1()
                out += _fmov_x0_d0()
            else:
                out += _mul(0, 0, 1)

        elif op == OP_DIV:
            if last_was_float:
                out += _fmov_d0_x0()
                out += _fdiv_d0_d0_d1()
                out += _fmov_x0_d0()
            else:
                out += _sdiv(0, 0, 1)

        # ---------- CMP ----------
        elif op == OP_CMP_EQ:
            if last_was_float:
                out += _fmov_d0_x0()
                out += _fcmp_d0_d1()
                out += _cset(0, 0x0)  # EQ
                last_was_float = False
            else:
                out += _cmp(0, 1)
                out += _cset(0, 0x0)  # EQ
                last_was_float = False

        elif op == OP_CMP_LT:
            if last_was_float:
                out += _fmov_d0_x0()
                out += _fcmp_d0_d1()
                out += _cset(0, 0xB)  # LT
                last_was_float = False
            else:
                out += _cmp(0, 1)
                out += _cset(0, 0xB)  # LT
                last_was_float = False

        elif op == OP_CMP_GT:
            if last_was_float:
                out += _fmov_d0_x0()
                out += _fcmp_d0_d1()
                out += _cset(0, 0xC)  # GT
                last_was_float = False
            else:
                out += _cmp(0, 1)
                out += _cset(0, 0xC)  # GT
                last_was_float = False

        # ---------- JMP ----------
        elif op == OP_JMP:
            fixups.append((len(out), a, "b"))
            out += _b(0)

        # ---------- JMP IF FALSE ----------
        elif op == OP_JMP_IF_FALSE:
            # branch if x0 == 0 (ints, pointers, bools; floats: nonzero bits = true)
            out += _cmp(0, 31)          # cmp x0, xzr
            fixups.append((len(out), a, "bz"))
            out += _b_cond(0, 0x0)      # b.eq

        # ---------- CALL ----------
        elif op == OP_CALL:
            argc = b

            # v1: move arguments into x0-x7 in trivial way
            # Strings/f-strings: Werte sind i64-Pointer, Backend ist typagnostisch
            for i_arg in range(argc):
                out += _mov_imm64(ABI_REGS[i_arg], 0)

            fixups.append((len(out), a, "bl"))
            out += _bl(0)
            last_was_float = False  # Rückgabewert-Typ unbekannt

        # ---------- RETURN ----------
        elif op == OP_RETURN:
            out += _add_sp(32)
            out += _ldp_fp_lr()
            out += _ret()

        else:
            raise RuntimeError(f"Unsupported opcode {op}")

    # ---------- resolve branches & calls ----------
    for pos_fix, target, kind in fixups:
        dst = labels[target]
        rel = dst - pos_fix

        if kind == "b":
            out[pos_fix:pos_fix + 4] = _b(rel)
        elif kind == "bz":
            out[pos_fix:pos_fix + 4] = _b_cond(rel, 0x0)
        elif kind == "bl":
            out[pos_fix:pos_fix + 4] = _bl(rel)

    # ---------- safety epilogue ----------
    out += _add_sp(32)
    out += _ldp_fp_lr()
    out += _ret()

    return bytes(out)
