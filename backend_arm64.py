# backend_arm64.py
# ============================================================
# Mantis 6 — ARM64 Backend
# True native translation (no libc, no runtime, no placeholders)
# ============================================================

from __future__ import annotations
import struct
import platform

# ============================================================
# Opcodes
# ============================================================

OP_LOADI  = 0x01
OP_ADD    = 0x02
OP_SUB    = 0x03
OP_MUL    = 0x04
OP_DIV    = 0x05
OP_RET    = 0x06
OP_PRINT  = 0x20
OP_READLN = 0x21

# ============================================================
# Syscall numbers (Linux / macOS ARM64)
# ============================================================

IS_DARWIN = platform.system() == "Darwin"

if IS_DARWIN:
    SYS_WRITE = 0x2000004
    SYS_READ  = 0x2000003
else:
    SYS_WRITE = 64
    SYS_READ  = 63

STDIN  = 0
STDOUT = 1

# ============================================================
# Helpers
# ============================================================

def _mov_imm(dst: int, imm: int) -> bytes:
    code = bytearray()

    for shift in (0, 16, 32, 48):
        part = (imm >> shift) & 0xFFFF
        if shift == 0:
            op = 0xD2800000  # MOVZ
        else:
            if part == 0:
                continue
            op = 0xF2800000  # MOVK

        op |= part << 5
        op |= dst
        code += struct.pack("<I", op)

    return bytes(code)


def _add(d, a, b):
    return struct.pack("<I", 0x8B000000 | (b << 16) | (a << 5) | d)


def _sub(d, a, b):
    return struct.pack("<I", 0xCB000000 | (b << 16) | (a << 5) | d)


def _mul(d, a, b):
    return struct.pack("<I", 0x9B007C00 | (b << 16) | (a << 5) | d)


def _udiv(d, a, b):
    return struct.pack("<I", 0x9AC00C00 | (b << 16) | (a << 5) | d)


def _ret(src):
    code = bytearray()

    if src != 0:
        code += _add(0, src, 31)  # move to x0

    code += struct.pack("<I", 0xD65F03C0)  # RET
    return bytes(code)


# ============================================================
# Native PRINT via write syscall
# ============================================================

def _emit_print(reg: int) -> bytes:
    """
    Writes 8-byte integer directly to stdout using syscall.
    """

    code = bytearray()

    # Reserve stack space for buffer
    code += struct.pack("<I", 0xD10043FF)  # sub sp, sp, #16

    # Store register to stack
    code += struct.pack("<I", 0xF90003E0 | (reg << 5))  # str xN, [sp]

    # fd → x0
    code += _mov_imm(0, STDOUT)

    # buf → x1
    code += struct.pack("<I", 0x910003E1)  # mov x1, sp

    # size → x2
    code += _mov_imm(2, 8)

    # syscall number → x8
    code += _mov_imm(8, SYS_WRITE)

    # svc #0
    code += struct.pack("<I", 0xD4000001)

    # restore stack
    code += struct.pack("<I", 0x910043FF)  # add sp, sp, #16

    return bytes(code)


# ============================================================
# Native READ via syscall
# ============================================================

def _emit_read(dst: int) -> bytes:
    code = bytearray()

    # Reserve stack
    code += struct.pack("<I", 0xD10043FF)  # sub sp, sp, #16

    # fd stdin
    code += _mov_imm(0, STDIN)

    # buf sp
    code += struct.pack("<I", 0x910003E1)

    # size
    code += _mov_imm(2, 8)

    # syscall
    code += _mov_imm(8, SYS_READ)
    code += struct.pack("<I", 0xD4000001)

    # load into dst
    code += struct.pack("<I", 0xF94003E0 | (dst))  # ldr xN, [sp]

    # restore stack
    code += struct.pack("<I", 0x910043FF)

    return bytes(code)


# ============================================================
# Translator
# ============================================================

def emit_arm64(bytecode: bytes) -> bytes:
    native = bytearray()
    size = len(bytecode)

    for i in range(0, size, 8):
        op, dst, s1, s2, imm = struct.unpack("<BBBBi", bytecode[i:i+8])

        if op == OP_LOADI:
            native += _mov_imm(dst, imm)
        elif op == OP_ADD:
            native += _add(dst, s1, s2)
        elif op == OP_SUB:
            native += _sub(dst, s1, s2)
        elif op == OP_MUL:
            native += _mul(dst, s1, s2)
        elif op == OP_DIV:
            native += _udiv(dst, s1, s2)
        elif op == OP_PRINT:
            native += _emit_print(dst)
        elif op == OP_READLN:
            native += _emit_read(dst)
        elif op == OP_RET:
            native += _ret(dst)
        else:
            raise RuntimeError(f"Unknown opcode {op}")

    return bytes(native)