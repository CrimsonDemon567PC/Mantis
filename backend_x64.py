# ============================================================
# Mantis 7 — Native x86-64 Backend
# Single-function MTN → x64 machine code
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
# LOW-LEVEL ENCODING HELPERS
# ============================================================

def _rex(w=1, r=0, x=0, b=0):
    return bytes([0x40 | (w << 3) | (r << 2) | (x << 1) | b])


def _modrm(mod, reg, rm):
    return bytes([(mod << 6) | ((reg & 7) << 3) | (rm & 7)])


def _mov_imm64(reg, imm):
    """
    mov rXX, imm64
    """
    return _rex(1, 0, 0, (reg >> 3) & 1) + bytes([0xB8 + (reg & 7)]) + struct.pack("<Q", imm)


def _rr(op, dst, src):
    """
    Generic REX + opcode + ModRM for register-to-register ops.
    dst, src are register indices (0..15).
    """
    return _rex(1, (src >> 3) & 1, 0, (dst >> 3) & 1) + op + _modrm(3, src, dst)


def _push_rbp():
    return b"\x55"


def _mov_rbp_rsp():
    return b"\x48\x89\xE5"


def _leave():
    return b"\xC9"


def _ret():
    return b"\xC3"


def _sub_rsp(v):
    return b"\x48\x81\xEC" + struct.pack("<I", v)


def _add_rsp(v):
    return b"\x48\x81\xC4" + struct.pack("<I", v)


def _cqo():
    return b"\x48\x99"


def _idiv(reg):
    """
    idiv rXX (signed divide RDX:RAX by rXX)
    """
    return _rex(1, 0, 0, (reg >> 3) & 1) + b"\xF7" + _modrm(3, 7, reg)


def _cmp(a, b):
    """
    cmp r/m64, r64
    Here: cmp b, a
    """
    return _rr(b"\x39", b, a)


def _setcc(op):
    """
    setcc al
    """
    return b"\x0F" + bytes([op]) + b"\xC0"


def _movzx_rax_al():
    """
    movzx rax, al
    """
    return b"\x48\x0F\xB6\xC0"


def _jmp_rel32():
    """
    jmp rel32 (patched later)
    """
    return b"\xE9\x00\x00\x00\x00"


def _jz_rel32():
    """
    jz rel32 (patched later)
    """
    return b"\x0F\x84\x00\x00\x00\x00"


def _call_rel32():
    """
    call rel32 (patched later)
    """
    return b"\xE8\x00\x00\x00\x00"


# ============================================================
# STACK ACCESS (RBP-RELATIVE)
# ============================================================

def _load_stack(offset):
    """
    mov rax, [rbp + offset]
    """
    return b"\x48\x8B\x85" + struct.pack("<i", offset)


def _store_stack(offset):
    """
    mov [rbp + offset], rax
    """
    return b"\x48\x89\x85" + struct.pack("<i", offset)


# ============================================================
# ABI ARGUMENT REGISTERS (System V AMD64)
# rdi, rsi, rdx, rcx, r8, r9
# ============================================================

ABI_REGS = [7, 6, 2, 1, 8, 9]


# ============================================================
# MAIN EMITTER
# ============================================================

def emit_x64(bytecode: bytes) -> bytes:
    """
    Translate a single-function MTN bytecode buffer into x86-64
    machine code. Uses a simple register convention:
    - rax is the primary value register
    - stack slots are addressed via rbp-relative offsets
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
    out += _push_rbp()
    out += _mov_rbp_rsp()
    out += _sub_rsp(32)  # fixed local space (v1)

    labels = []  # byte offset of each instruction
    fixups = []  # (patch_pos, target_index)

    for i, (op, a, b, c) in enumerate(instrs):

        labels.append(len(out))

        # ---------- CONST ----------
        if op == OP_CONST_I64:
            out += _mov_imm64(0, a)

        # ---------- LOAD / STORE ----------
        elif op == OP_LOAD:
            out += _load_stack(a)

        elif op == OP_STORE:
            out += _store_stack(a)

        # ---------- ARITH ----------
        elif op == OP_ADD:
            out += _rr(b"\x01", 0, 3)  # add rax, rbx

        elif op == OP_SUB:
            out += _rr(b"\x29", 0, 3)  # sub rax, rbx

        elif op == OP_MUL:
            out += _rr(b"\x0F\xAF", 0, 3)  # imul rax, rbx

        elif op == OP_DIV:
            out += _cqo()
            out += _idiv(3)  # idiv rbx

        # ---------- CMP ----------
        elif op == OP_CMP_EQ:
            out += _cmp(0, 3)
            out += _setcc(0x94)  # sete
            out += _movzx_rax_al()

        elif op == OP_CMP_LT:
            out += _cmp(0, 3)
            out += _setcc(0x9C)  # setl
            out += _movzx_rax_al()

        elif op == OP_CMP_GT:
            out += _cmp(0, 3)
            out += _setcc(0x9F)  # setg
            out += _movzx_rax_al()

        # ---------- JMP ----------
        elif op == OP_JMP:
            fixups.append((len(out) + 1, a))
            out += _jmp_rel32()

        # ---------- JMP IF FALSE ----------
        elif op == OP_JMP_IF_FALSE:
            # compare rax with 0
            out += _cmp(0, 0)
            fixups.append((len(out) + 2, a))
            out += _jz_rel32()

        # ---------- CALL ----------
        elif op == OP_CALL:
            argc = b

            # move arguments into ABI registers
            # (v1: assumes values are already in registers/stack)
            for i_arg in range(argc):
                reg = ABI_REGS[i_arg]
                out += _rr(b"\x89", reg, 0)  # mov reg, rax (simple model)

            fixups.append((len(out) + 1, a))
            out += _call_rel32()

        # ---------- RETURN ----------
        elif op == OP_RETURN:
            out += _add_rsp(32)
            out += _leave()
            out += _ret()

        else:
            raise RuntimeError(f"Unsupported opcode {op}")

    # ---------- resolve branches & calls ----------
    for pos_fix, target in fixups:
        src = pos_fix + 4
        dst = labels[target]
        rel = dst - src
        out[pos_fix:pos_fix + 4] = struct.pack("<i", rel)

    # safety epilogue (in case of fallthrough)
    out += _add_rsp(32)
    out += _leave()
    out += _ret()

    return bytes(out)
