# ============================================================
# Mantis 7 — Native ARM64 Backend
# Single-function MTN → AArch64 machine code
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
# ENCODING HELPERS
# ============================================================

def _u32(x: int) -> bytes:
    return struct.pack("<I", x)


def _mov_imm64_x0(value: int) -> bytes:
    """
    Load a 64-bit immediate into x0 using MOVZ/MOVK.
    v1: simple 3-part sequence (lower 48 bits are enough for most cases).
    """
    lo16  =  value        & 0xFFFF
    mid16 = (value >> 16) & 0xFFFF
    hi16  = (value >> 32) & 0xFFFF

    ins = []
    ins.append(0xD2800000 | (lo16 << 5))   # movz x0, lo16
    ins.append(0xF2A00000 | (mid16 << 5)) # movk x0, mid16, lsl #16
    ins.append(0xF2C00000 | (hi16 << 5))  # movk x0, hi16, lsl #32
    return b"".join(_u32(i) for i in ins)


def _load_stack(offset: int) -> bytes:
    """
    ldr x0, [x29, #offset]
    x29 is the frame pointer (fp).
    """
    imm = offset // 8
    return _u32(0xF9400000 | (imm << 10) | 29 << 5 | 0)


def _store_stack(offset: int) -> bytes:
    """
    str x0, [x29, #offset]
    """
    imm = offset // 8
    return _u32(0xF9000000 | (imm << 10) | 29 << 5 | 0)


def _add_x0_x0_x1() -> bytes:
    return _u32(0x8B010000)  # add x0, x0, x1


def _sub_x0_x0_x1() -> bytes:
    return _u32(0xCB010000)  # sub x0, x0, x1


def _mul_x0_x0_x1() -> bytes:
    return _u32(0x9B017C00)  # mul x0, x0, x1


def _sdiv_x0_x0_x1() -> bytes:
    return _u32(0x9AC10C00)  # sdiv x0, x0, x1


def _cmp_x0_x1() -> bytes:
    return _u32(0xEB01001F)  # cmp x0, x1


def _cset_x0_eq() -> bytes:
    return _u32(0x9A9F17E0)  # cset x0, eq


def _cset_x0_lt() -> bytes:
    return _u32(0x9A9F13E0)  # cset x0, lt


def _cset_x0_gt() -> bytes:
    return _u32(0x9A9F1BE0)  # cset x0, gt


def _b_cond(op: int) -> bytes:
    """
    Conditional branch with placeholder imm19.
    op is the condition code in the low 4 bits.
    """
    return _u32(0x54000000 | (op & 0xF))


def _b_uncond() -> bytes:
    return _u32(0x14000000)  # b <imm19>, patched later


def _bl() -> bytes:
    return _u32(0x94000000)  # bl <imm26>, patched later


def _cbz_x0() -> bytes:
    return _u32(0xB4000000)  # cbz x0, <imm19>, patched later


def _stp_fp_lr_pre() -> bytes:
    return _u32(0xA9BF7BF0)  # stp x29, x30, [sp, #-16]!


def _ldp_fp_lr_post() -> bytes:
    return _u32(0xA8C17BF0)  # ldp x29, x30, [sp], #16


def _mov_fp_sp() -> bytes:
    return _u32(0x910003FD)  # mov x29, sp


def _sub_sp_imm(imm: int) -> bytes:
    # sub sp, sp, #imm (imm multiple of 16)
    return _u32(0xD10003FF | ((imm & 0xFFF) << 10))


def _add_sp_imm(imm: int) -> bytes:
    # add sp, sp, #imm
    return _u32(0x910003FF | ((imm & 0xFFF) << 10))


# ============================================================
# ABI ARGUMENT REGISTERS (AArch64)
# x0, x1, x2, x3, x4, x5
# ============================================================

ABI_REGS = [0, 1, 2, 3, 4, 5]


# ============================================================
# MAIN EMITTER
# ============================================================

def emit_arm64(bytecode: bytes, rt_offsets: dict[str, int]) -> bytes:
    """
    Translate a single-function MTN bytecode buffer into AArch64
    machine code.

    Conventions:
      - x0 is the primary value register
      - x1 is the secondary value register
      - stack slots are addressed via x29-relative offsets
      - floats are not yet handled in v1 (F64 opcodes still map to raw bits)

    rt_offsets are offsets (in bytes) of runtime functions
    relative to the start of the runtime blob that will be
    appended directly after this code.
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

    instrs: list[tuple[int, int, int, int]] = []
    for _ in range(code_len):
        op, a, b, c = struct.unpack_from("<Biii", bytecode, pos)
        pos += 13
        instrs.append((op, a, b, c))

    out = bytearray()

    # ---------- prologue ----------
    out += _stp_fp_lr_pre()
    out += _mov_fp_sp()
    out += _sub_sp_imm(32)  # fixed local space for v1

    labels: list[int] = []
    fixups_branch: list[tuple[int, int]] = []      # (pos, target_index) for intra-code branches/calls
    builtin_fixups: list[tuple[int, int]] = []     # (pos, rt_offset) for runtime BL calls
    last_was_float = False

    for i, (op, a, b, c) in enumerate(instrs):
        labels.append(len(out))

        # ---------- CONSTANTS ----------
        if op == OP_CONST_I64:
            out += _mov_imm64_x0(a)
            last_was_float = False

        elif op == OP_CONST_F64:
            out += _mov_imm64_x0(a)
            last_was_float = True

        # ---------- LOAD / STORE ----------
        elif op == OP_LOAD:
            out += _load_stack(a)
            last_was_float = False

        elif op == OP_STORE:
            out += _store_stack(a)

        # ---------- ARITHMETIC ----------
        elif op == OP_ADD:
            out += _add_x0_x0_x1()
            last_was_float = False

        elif op == OP_SUB:
            out += _sub_x0_x0_x1()
            last_was_float = False

        elif op == OP_MUL:
            out += _mul_x0_x0_x1()
            last_was_float = False

        elif op == OP_DIV:
            out += _sdiv_x0_x0_x1()
            last_was_float = False

        # ---------- COMPARISONS ----------
        elif op == OP_CMP_EQ:
            out += _cmp_x0_x1()
            out += _cset_x0_eq()
            last_was_float = False

        elif op == OP_CMP_LT:
            out += _cmp_x0_x1()
            out += _cset_x0_lt()
            last_was_float = False

        elif op == OP_CMP_GT:
            out += _cmp_x0_x1()
            out += _cset_x0_gt()
            last_was_float = False

        # ---------- JUMPS ----------
        elif op == OP_JMP:
            fixups_branch.append((len(out), a))
            out += _b_uncond()

        elif op == OP_JMP_IF_FALSE:
            out += _cbz_x0()
            fixups_branch.append((len(out) - 4, a))

        # ---------- CALLS ----------
        elif op == OP_CALL:
            argc = b

            # Move arguments into ABI registers (x0, x1, x2, ...)
            for i_arg in range(argc):
                reg = ABI_REGS[i_arg]
                if reg != 0:
                    out += _u32(0xAA0003E0 | (reg << 5))  # mov xN, x0

            if a < 0:
                # Builtin calls mapped to runtime blob.
                if a == -2:
                    rt_off = rt_offsets["concat"]
                elif a == -3:
                    rt_off = rt_offsets["format_i64"]
                elif a == -1:
                    # print builtin not mapped natively in v1
                    rt_off = None
                else:
                    raise RuntimeError(f"Unknown builtin call {a}")

                if rt_off is not None:
                    pos = len(out)
                    out += _bl()
                    builtin_fixups.append((pos, rt_off))

                last_was_float = False
            else:
                # Normal function calls (by instruction index).
                fixups_branch.append((len(out), a))
                out += _bl()
                last_was_float = False

        # ---------- RETURN ----------
        elif op == OP_RETURN:
            out += _add_sp_imm(32)
            out += _ldp_fp_lr_post()
            out += _u32(0xD65F03C0)  # ret

        else:
            raise RuntimeError(f"Unsupported opcode {op}")

    code_size = len(out)

    # ---------- resolve intra-code branches and calls ----------
    for pos, target in fixups_branch:
        src = pos
        dst = labels[target]
        ins = struct.unpack_from("<I", out, pos)[0]
        if (ins & 0x7C000000) == 0x14000000:
            # B or BL: imm26
            imm26 = (dst - src) >> 2
            ins = (ins & 0xFC000000) | (imm26 & 0x03FFFFFF)
        else:
            # CBZ/B.cond: imm19
            imm19 = (dst - src) >> 2
            ins = (ins & 0xFF00001F) | ((imm19 & 0x7FFFF) << 5)
        out[pos:pos+4] = _u32(ins)

    # ---------- resolve builtin BL calls into runtime blob ----------
    for pos, rt_off in builtin_fixups:
        src = pos
        dst = code_size + rt_off
        imm26 = (dst - src) >> 2
        ins = 0x94000000 | (imm26 & 0x03FFFFFF)
        out[pos:pos+4] = _u32(ins)

    # Safety epilogue in case of fallthrough
    out += _add_sp_imm(32)
    out += _ldp_fp_lr_post()
    out += _u32(0xD65F03C0)

    return bytes(out)
