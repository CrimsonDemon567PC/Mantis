# ============================================================
# Mantis 7 — Embedded String Runtime (x64 + ARM64)
# Fully position‑independent machine‑code blobs
# Designed to be appended to the generated Mantis code
#
# Provides:
#   - __mantis_strlen
#   - __mantis_memcpy
#   - __mantis_string_concat
#
# Two architectures:
#   - StringRuntimeX64
#   - StringRuntimeARM64
#
# loader.py usage:
#     from string_runtime import StringRuntimeX64
#     runtime = StringRuntimeX64().build()
#     blob = code + runtime
# ============================================================

from __future__ import annotations
import struct


# ============================================================
# Base class for shared helpers
# ============================================================

class _RuntimeBase:
    def __init__(self, heap_size: int = 64 * 1024):
        self.heap_size = heap_size

    def _i32(self, x: int) -> bytes:
        return struct.pack("<i", x)


# ============================================================
# X86‑64 STRING RUNTIME
# ============================================================

class StringRuntimeX64(_RuntimeBase):
    """
    Produces a fully position‑independent x86‑64 string runtime.
    Contains:
        __mantis_strlen
        __mantis_memcpy
        __mantis_string_concat
    plus a bump‑allocated heap appended after the code.
    """

    def build(self) -> bytes:
        out = bytearray()
        labels = {}
        fixups = []

        def mark(name: str):
            labels[name] = len(out)

        def jrel(op: bytes, target: str):
            pos = len(out)
            out.extend(op)
            fixups.append((pos + 1, target))

        # ====================================================
        # __mantis_strlen
        # ====================================================
        mark("__mantis_strlen")
        out += b"\x48\x89\xF8"          # mov rax, rdi
        mark("strlen_loop")
        out += b"\x80\x38\x00"          # cmp byte ptr [rax], 0
        jrel(b"\x0F\x84\x00\x00\x00\x00", "strlen_done")
        out += b"\x48\xFF\xC0"          # inc rax
        jrel(b"\xE9\x00\x00\x00\x00", "strlen_loop")
        mark("strlen_done")
        out += b"\x48\x29\xF8"          # sub rax, rdi
        out += b"\xC3"                  # ret

        # ====================================================
        # __mantis_memcpy
        # ====================================================
        mark("__mantis_memcpy")
        out += b"\x48\x89\xF8"          # mov rax, rdi
        out += b"\x48\x85\xD2"          # test rdx, rdx
        jrel(b"\x0F\x84\x00\x00\x00\x00", "memcpy_done")
        mark("memcpy_loop")
        out += b"\x8A\x1E"              # mov bl, [rsi]
        out += b"\x88\x1F"              # mov [rdi], bl
        out += b"\x48\xFF\xC6"          # inc rsi
        out += b"\x48\xFF\xC7"          # inc rdi
        out += b"\x48\xFF\xCA"          # dec rdx
        jrel(b"\x0F\x85\x00\x00\x00\x00", "memcpy_loop")
        mark("memcpy_done")
        out += b"\xC3"

        # ====================================================
        # __mantis_string_concat
        # ====================================================
        mark("__mantis_string_concat")

        # Save registers
        out += b"\x53"          # push rbx
        out += b"\x41\x52"      # push r10
        out += b"\x41\x53"      # push r11
        out += b"\x57"          # push rdi (save a)
        out += b"\x56"          # push rsi (save b)

        # len_a = strlen(a)
        out += b"\x48\x89\xFF"  # mov rdi, rdi
        rel = labels["__mantis_strlen"] - (len(out) + 5)
        out += b"\xE8" + self._i32(rel)
        out += b"\x49\x89\xC2"  # mov r10, rax

        # len_b = strlen(b)
        out += b"\x48\x89\xF7"  # mov rdi, rsi
        rel = labels["__mantis_strlen"] - (len(out) + 5)
        out += b"\xE8" + self._i32(rel)
        out += b"\x49\x89\xC3"  # mov r11, rax

        # total = len_a + len_b
        out += b"\x4D\x01\xDA"  # add r10, r11

        # rdx = total + 1
        out += b"\x4C\x89\xD2"  # mov rdx, r10
        out += b"\x48\xFF\xC2"  # inc rdx

        # Load heap_ptr (RIP‑relative)
        mark("heap_ptr_lea")
        out += b"\x48\x8D\x05\x00\x00\x00\x00"
        heap_ptr_patch = len(out) - 4

        out += b"\x48\x8B\x18"  # mov rbx, [rax]
        out += b"\x48\x85\xDB"  # test rbx, rbx
        jrel(b"\x0F\x85\x00\x00\x00\x00", "heap_inited")

        # init heap_ptr = rax + 8
        out += b"\x48\x8D\x58\x08"
        out += b"\x48\x89\x18"

        mark("heap_inited")

        # rcx = result
        out += b"\x48\x89\xD9"

        # bump
        out += b"\x48\x01\xD3"
        out += b"\x48\x89\x18"

        # rax = result
        out += b"\x48\x89\xC8"

        # memcpy(result, a, len_a)
        out += b"\x48\x89\xC7"  # mov rdi, rax
        out += b"\x4C\x89\xD2"  # mov rdx, r10
        out += b"\x5E"          # pop rsi (b)
        out += b"\x5F"          # pop rdi (a)
        out += b"\x48\x89\xF6"  # mov rsi, rsi (a)
        rel = labels["__mantis_memcpy"] - (len(out) + 5)
        out += b"\xE8" + self._i32(rel)

        # memcpy(result + len_a, b, len_b)
        out += b"\x48\x01\xD0"  # add rax, rdx
        out += b"\x48\x89\xC7"  # mov rdi, rax
        out += b"\x48\x89\xF6"  # mov rsi, rsi (b)
        out += b"\x4C\x89\xDA"  # mov rdx, r11
        rel = labels["__mantis_memcpy"] - (len(out) + 5)
        out += b"\xE8" + self._i32(rel)

        # null‑terminate
        out += b"\xC6\x00\x00"

        # restore registers
        out += b"\x41\x5B"  # pop r11
        out += b"\x41\x5A"  # pop r10
        out += b"\x5B"      # pop rbx

        out += b"\xC3"      # ret

        # ====================================================
        # Append heap_ptr + heap
        # ====================================================
        heap_ptr_offset = len(out)
        out += b"\x00" * 8
        out += b"\x00" * self.heap_size

        # ====================================================
        # Patch jumps
        # ====================================================
        for pos, target in fixups:
            src = pos + 4
            dst = labels[target]
            rel = dst - src
            out[pos:pos+4] = self._i32(rel)

        # Patch heap_ptr LEA
        rip_after = heap_ptr_patch + 4
        rel = heap_ptr_offset - rip_after
        out[heap_ptr_patch:heap_ptr_patch+4] = self._i32(rel)

        return bytes(out)

# ============================================================
# ARM64 STRING RUNTIME
# ============================================================

class StringRuntimeARM64(_RuntimeBase):
    """
    Produces a fully position‑independent ARM64 string runtime.
    Contains:
        __mantis_strlen
        __mantis_memcpy
        __mantis_string_concat
    plus a bump‑allocated heap appended after the code.
    """

    def build(self) -> bytes:
        out = bytearray()
        labels = {}
        fixups = []

        def mark(name: str):
            labels[name] = len(out)

        def jrel(op: int, target: str):
            """
            Insert a 32‑bit branch instruction with placeholder offset.
            op = base opcode (B, B.cond, BL)
            """
            pos = len(out)
            out.extend(struct.pack("<I", op))
            fixups.append((pos, target, op))

        # ====================================================
        # __mantis_strlen
        #   x0 = s
        #   returns length in x0
        # ====================================================
        mark("__mantis_strlen")

        # mov x1, x0
        out += self._u32(0xAA0003E1)  # mov x1, x0

        mark("strlen_loop")
        # ldrb w2, [x1]
        out += self._u32(0x39400022)
        # cbz w2, done
        jrel(0x34000000, "strlen_done")
        # add x1, x1, #1
        out += self._u32(0x91000421)
        # b loop
        jrel(0x14000000, "strlen_loop")

        mark("strlen_done")
        # sub x0, x1, x0
        out += self._u32(0xCB000020)
        # ret
        out += self._u32(0xD65F03C0)

        # ====================================================
        # __mantis_memcpy
        #   x0 = dst, x1 = src, x2 = n
        #   returns dst in x0
        # ====================================================
        mark("__mantis_memcpy")

        # cbz x2, done
        jrel(0xB4000000, "memcpy_done")

        mark("memcpy_loop")
        # ldrb w3, [x1]
        out += self._u32(0x39400023)
        # strb w3, [x0]
        out += self._u32(0x39000003)
        # add x1, x1, #1
        out += self._u32(0x91000421)
        # add x0, x0, #1
        out += self._u32(0x91000400)
        # sub x2, x2, #1
        out += self._u32(0xD1000442)
        # cbnz x2, loop
        jrel(0x35000000, "memcpy_loop")

        mark("memcpy_done")
        out += self._u32(0xD65F03C0)  # ret

        # ====================================================
        # __mantis_string_concat
        #   x0 = a
        #   x1 = b
        #   returns pointer in x0
        # ====================================================
        mark("__mantis_string_concat")

        # Save registers: x19,x20,x21,x22
        out += self._u32(0xA9BF4FF3)  # stp x19,x20,[sp,#-16]!
        out += self._u32(0xA9BF57F5)  # stp x21,x22,[sp,#-16]!

        # Save a,b
        out += self._u32(0xAA0003F3)  # mov x19, x0 (a)
        out += self._u32(0xAA0103F4)  # mov x20, x1 (b)

        # len_a = strlen(a)
        out += self._u32(0xAA1303E0)  # mov x0, x19
        jrel(0x94000000, "__mantis_strlen")
        out += self._u32(0xAA0003F5)  # mov x21, x0

        # len_b = strlen(b)
        out += self._u32(0xAA1403E0)  # mov x0, x20
        jrel(0x94000000, "__mantis_strlen")
        out += self._u32(0xAA0003F6)  # mov x22, x0

        # total = len_a + len_b
        out += self._u32(0x8B1602B5)  # add x21, x21, x22

        # x2 = total + 1
        out += self._u32(0xAA1503E2)  # mov x2, x21
        out += self._u32(0x91000442)  # add x2, x2, #1

        # Load heap_ptr (RIP‑relative)
        mark("heap_ptr_adr")
        out += self._u32(0x58000080)  # ldr x0, #imm19 (patched later)
        heap_ptr_patch = len(out) - 4

        # ldr x1, [x0]
        out += self._u32(0xF9400001)
        # cbnz x1, heap_inited
        jrel(0x35000000, "heap_inited")

        # init heap_ptr = x0 + 8
        out += self._u32(0x91002001)  # add x1, x0, #8
        out += self._u32(0xF9000001)  # str x1, [x0]

        mark("heap_inited")

        # x3 = result = x1
        out += self._u32(0xAA0103E3)

        # bump: x1 += x2
        out += self._u32(0x8B020021)
        # store new heap_ptr
        out += self._u32(0xF9000001)

        # return ptr in x0
        out += self._u32(0xAA0303E0)

        # memcpy(result, a, len_a)
        out += self._u32(0xAA0303E0)  # mov x0, x3
        out += self._u32(0xAA1303E1)  # mov x1, x19
        out += self._u32(0xAA1503E2)  # mov x2, x21
        jrel(0x94000000, "__mantis_memcpy")

        # memcpy(result + len_a, b, len_b)
        out += self._u32(0x8B150060)  # add x0, x3, x21
        out += self._u32(0xAA1403E1)  # mov x1, x20
        out += self._u32(0xAA1603E2)  # mov x2, x22
        jrel(0x94000000, "__mantis_memcpy")

        # null‑terminate
        out += self._u32(0x3900001F)  # strb wzr, [x0]

        # restore registers
        out += self._u32(0xA8C157F5)  # ldp x21,x22,[sp],#16
        out += self._u32(0xA8C14FF3)  # ldp x19,x20,[sp],#16

        out += self._u32(0xD65F03C0)  # ret

        # ====================================================
        # Append heap_ptr + heap
        # ====================================================
        heap_ptr_offset = len(out)
        out += b"\x00" * 8
        out += b"\x00" * self.heap_size

        # ====================================================
        # Patch branches
        # ====================================================
        for pos, target, op in fixups:
            src = pos
            dst = labels[target]
            rel = (dst - src) >> 2
            out[pos:pos+4] = struct.pack("<I", (op & 0xFC000000) | (rel & 0x03FFFFFF))

        # Patch heap_ptr ADR (ldr literal)
        # ldr x0, #imm19 → imm19 = (heap_ptr_offset - PC) >> 2
        pc = heap_ptr_patch
        imm19 = (heap_ptr_offset - pc) >> 2
        out[heap_ptr_patch:heap_ptr_patch+4] = struct.pack("<I", 0x58000000 | ((imm19 & 0x7FFFF) << 5) | 0)

        return bytes(out)
