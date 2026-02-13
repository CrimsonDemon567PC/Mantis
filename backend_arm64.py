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

    for i, (op, a, b, c) in enumerate(instrs):

        labels.append(len(out))

        # ---------- CONST ----------
        if op == OP_CONST_I64:
            out += _mov_imm64(0, a)

        elif op == OP_CONST_F64:
            # v1: treat F64 constant as raw 64-bit payload in x0
            # (no separate FP pipeline yet)
            out += _mov_imm64(0, a)

        # ---------- LOAD / STORE ----------
        elif op == OP_LOAD:
            out += _ldr_stack(0, a)

        elif op == OP_STORE:
            out += _str_stack(0, a)

        # ---------- ARITH ----------
        elif op == OP_ADD:
            out += _add(0, 0, 1)

        elif op == OP_SUB:
            out += _sub(0, 0, 1)

        elif op == OP_MUL:
            out += _mul(0, 0, 1)

        elif op == OP_DIV:
            out += _sdiv(0, 0, 1)

        # ---------- CMP ----------
        elif op == OP_CMP_EQ:
            out += _cmp(0, 1)
            out += _cset(0, 0x0)  # EQ

        elif op == OP_CMP_LT:
            out += _cmp(0, 1)
            out += _cset(0, 0xB)  # LT

        elif op == OP_CMP_GT:
            out += _cmp(0, 1)
            out += _cset(0, 0xC)  # GT

        # ---------- JMP ----------
        elif op == OP_JMP:
            fixups.append((len(out), a, "b"))
            out += _b(0)

        # ---------- JMP IF FALSE ----------
        elif op == OP_JMP_IF_FALSE:
            # branch if x0 == 0 (false)
            out += _cmp(0, 31)          # cmp x0, xzr
            fixups.append((len(out), a, "bz"))
            out += _b_cond(0, 0x0)      # b.eq

        # ---------- CALL ----------
        elif op == OP_CALL:
            argc = b

            # v1: move arguments into x0-x7 in a trivial way
            # (hier nur Platzhalter, da das aktuelle IR keine
            #  echten Multi-Register-Argumente modelliert)
            for i_arg in range(argc):
                out += _mov_imm64(ABI_REGS[i_arg], 0)

            fixups.append((len(out), a, "bl"))
            out += _bl(0)

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
