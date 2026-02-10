from __future__ import annotations
import ctypes
import platform
import struct

# ============================================================
# OPCODES  (muss exakt zu compiler.py passen)
# ============================================================

OP_LOADI   = 0x01
OP_ADD     = 0x02
OP_SUB     = 0x03
OP_MUL     = 0x04
OP_DIV     = 0x05
OP_RET     = 0x06
OP_PRINT   = 0x20
OP_READLN  = 0x21

# ============================================================
# REX / MODRM ENCODING
# ============================================================

def _rex(w: int, r: int, x: int, b: int) -> bytes:
    return bytes([0x40 | (w << 3) | (r << 2) | (x << 1) | b])


def _modrm(mod: int, reg: int, rm: int) -> bytes:
    return bytes([(mod << 6) | ((reg & 7) << 3) | (rm & 7)])


def _encode_rr(op: bytes, dst: int, src: int) -> bytes:
    """
    dst = rm field
    src = reg field
    """
    return (
        _rex(1, (src >> 3) & 1, 0, (dst >> 3) & 1)
        + op
        + _modrm(3, src, dst)
    )


def _mov_imm64(reg: int, imm: int) -> bytes:
    return (
        _rex(1, 0, 0, (reg >> 3) & 1)
        + bytes([0xB8 + (reg & 7)])
        + struct.pack("<Q", imm & 0xFFFFFFFFFFFFFFFF)
    )


# ============================================================
# SYSTEM / LIBC
# ============================================================

_system = platform.system()

if _system == "Windows":
    libc = ctypes.CDLL("msvcrt.dll")
else:
    libc = ctypes.CDLL(None)

printf_addr = ctypes.cast(libc.printf, ctypes.c_void_p).value
scanf_addr  = ctypes.cast(libc.scanf,  ctypes.c_void_p).value

PRINTF_FMT = ctypes.create_string_buffer(b"%lld\n")
SCANF_FMT  = ctypes.create_string_buffer(b"%lld")

printf_fmt_addr = ctypes.addressof(PRINTF_FMT)
scanf_fmt_addr  = ctypes.addressof(SCANF_FMT)

# ============================================================
# CALL HELPERS (ABI-KORREKT)
# ============================================================

def _call_abs(addr: int) -> bytes:
    # mov rax, addr ; call rax
    return _mov_imm64(0, addr) + b"\xFF\xD0"


def _setup_printf(val_reg: int) -> bytes:
    if _system == "Windows":
        # rcx, rdx
        return (
            _mov_imm64(1, printf_fmt_addr) +
            _encode_rr(b"\x89", 2, val_reg)
        )
    else:
        # rdi, rsi
        return (
            _mov_imm64(7, printf_fmt_addr) +
            _encode_rr(b"\x89", 6, val_reg)
        )


def _setup_scanf() -> tuple[bytes, ctypes.Array, int]:
    buf = ctypes.create_string_buffer(8)
    addr = ctypes.addressof(buf)

    if _system == "Windows":
        setup = (
            _mov_imm64(1, scanf_fmt_addr) +
            _mov_imm64(2, addr)
        )
    else:
        setup = (
            _mov_imm64(7, scanf_fmt_addr) +
            _mov_imm64(6, addr)
        )

    return setup, buf, addr


# ============================================================
# MAIN EMITTER
# ============================================================

def emit_x64(bytecode: bytes) -> bytes:
    code = bytearray()

    # --------------------------------------------------------
    # PROLOG  (STACK ALIGNMENT + SHADOW SPACE)
    # --------------------------------------------------------

    code += b"\x55"              # push rbp
    code += b"\x48\x89\xE5"      # mov rbp, rsp

    if _system == "Windows":
        code += b"\x48\x83\xEC\x28"  # sub rsp, 40
    else:
        code += b"\x48\x83\xEC\x08"  # sub rsp, 8

    # --------------------------------------------------------
    # BYTECODE LOOP
    # --------------------------------------------------------

    pc = 0
    size = len(bytecode)

    while pc < size:
        op  = bytecode[pc]
        dst = bytecode[pc+1]
        s1  = bytecode[pc+2]
        s2  = bytecode[pc+3]
        imm = struct.unpack_from("<i", bytecode, pc+4)[0]
        pc += 8

        # ---------------- LOADI ----------------
        if op == OP_LOADI:
            code += _mov_imm64(dst, imm)

        # ---------------- ADD ------------------
        elif op == OP_ADD:
            code += _encode_rr(b"\x01", dst, s1)

        # ---------------- SUB ------------------
        elif op == OP_SUB:
            code += _encode_rr(b"\x29", dst, s1)

        # ---------------- MUL ------------------
        elif op == OP_MUL:
            code += _encode_rr(b"\x0F\xAF", dst, s1)

        # ---------------- DIV (RDX SAFE) -------
        elif op == OP_DIV:
            code += b"\x52"                      # push rdx
            code += _encode_rr(b"\x89", 0, dst)  # mov rax, dst
            code += b"\x48\x99"                  # cqo

            rex = _rex(1, 0, 0, (s1 >> 3) & 1)
            modrm = _modrm(3, 7, s1)
            code += rex + b"\xF7" + modrm        # idiv r/m64

            code += _encode_rr(b"\x89", dst, 0)  # dst = rax
            code += b"\x5A"                      # pop rdx

        # ---------------- PRINT ----------------
        elif op == OP_PRINT:
            code += _setup_printf(dst)
            code += _call_abs(printf_addr)

        # ---------------- READLN ---------------
        elif op == OP_READLN:
            setup, buf, addr = _setup_scanf()
            code += setup
            code += _call_abs(scanf_addr)
            code += _mov_imm64(dst, addr)
            code += _encode_rr(b"\x8B", dst, dst)

        # ---------------- RET ------------------
        elif op == OP_RET:
            code += _encode_rr(b"\x89", 0, dst)  # rax = dst

            if _system == "Windows":
                code += b"\x48\x83\xC4\x28"      # add rsp, 40
            else:
                code += b"\x48\x83\xC4\x08"      # add rsp, 8

            code += b"\x5D"  # pop rbp
            code += b"\xC3"  # ret

        else:
            raise RuntimeError(f"Unknown opcode {op}")

    return bytes(code)
