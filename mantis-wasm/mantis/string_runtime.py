# ============================================================
# Mantis 7 — Embedded String Runtime (x64 + ARM64)
# Fully position‑independent machine‑code blobs
# Designed to be appended to the generated Mantis code
#
# Provides:
#   - __mantis_strlen
#   - __mantis_memcpy
#   - __mantis_string_concat
#   - __mantis_format_i64
#
# build() now returns: (blob, offsets)
# offsets = {
#     "strlen": <offset>,
#     "memcpy": <offset>,
#     "concat": <offset>,
#     "format_i64": <offset>,
# }
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
        __mantis_format_i64
    plus a bump‑allocated heap appended after the code.

    build() returns (blob, offsets)
    """

    def build(self) -> tuple[bytes, dict[str, int]]:
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
        out += b"\xC3"

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

        out += b"\x53"          # push rbx
        out += b"\x41\x52"      # push r10
        out += b"\x41\x53"      # push r11
        out += b"\x57"          # push rdi
        out += b"\x56"          # push rsi

        # len_a
        out += b"\x48\x89\xFF"
        rel = labels["__mantis_strlen"] - (len(out) + 5)
        out += b"\xE8" + self._i32(rel)
        out += b"\x49\x89\xC2"

        # len_b
        out += b"\x48\x89\xF7"
        rel = labels["__mantis_strlen"] - (len(out) + 5)
        out += b"\xE8" + self._i32(rel)
        out += b"\x49\x89\xC3"

        # total = r10 + r11
        out += b"\x4D\x01\xDA"

        # rdx = total + 1
        out += b"\x4C\x89\xD2"
        out += b"\x48\xFF\xC2"

        # heap_ptr load
        mark("heap_ptr_lea")
        out += b"\x48\x8D\x05\x00\x00\x00\x00"
        heap_ptr_patch = len(out) - 4

        out += b"\x48\x8B\x18"
        out += b"\x48\x85\xDB"
        jrel(b"\x0F\x85\x00\x00\x00\x00", "heap_inited")

        out += b"\x48\x8D\x58\x08"
        out += b"\x48\x89\x18"

        mark("heap_inited")

        out += b"\x48\x89\xD9"  # rcx = result

        out += b"\x48\x01\xD3"  # bump
        out += b"\x48\x89\x18"

        out += b"\x48\x89\xC8"  # rax = result

        # memcpy(result, a, len_a)
        out += b"\x48\x89\xC7"
        out += b"\x4C\x89\xD2"
        out += b"\x5E"
        out += b"\x5F"
        out += b"\x48\x89\xF6"
        rel = labels["__mantis_memcpy"] - (len(out) + 5)
        out += b"\xE8" + self._i32(rel)

        # memcpy(result+len_a, b, len_b)
        out += b"\x48\x01\xD0"
        out += b"\x48\x89\xC7"
        out += b"\x48\x89\xF6"
        out += b"\x4C\x89\xDA"
        rel = labels["__mantis_memcpy"] - (len(out) + 5)
        out += b"\xE8" + self._i32(rel)

        out += b"\xC6\x00\x00"  # null

        out += b"\x41\x5B"
        out += b"\x41\x5A"
        out += b"\x5B"
        out += b"\xC3"

        # ====================================================
        # __mantis_format_i64
        # ====================================================
        mark("__mantis_format_i64")

        out += b"\x53"          # push rbx
        out += b"\x41\x50"      # push r8
        out += b"\x41\x51"      # push r9

        out += b"\x48\x89\xFB"  # mov rbx, rdi

        # sign
        out += b"\x48\x89\xDF"
        out += b"\x48\xC1\xEF\x3F"
        out += b"\x48\x21\xDF"
        out += b"\x48\x29\xDF"
        out += b"\x48\x31\xDB"
        out += b"\x48\x0F\x44\xDF"

        # heap_ptr
        mark("fmt_heap_lea")
        out += b"\x48\x8D\x05\x00\x00\x00\x00"
        fmt_heap_patch = len(out) - 4

        out += b"\x48\x8B\x00"
        out += b"\x48\x85\xC0"
        jrel(b"\x0F\x85\x00\x00\x00\x00", "fmt_heap_inited")

        out += b"\x48\x8D\x40\x08"
        out += b"\x48\x89\x00"

        mark("fmt_heap_inited")

        out += b"\x49\x89\xC0"  # r8 = buf

        out += b"\x48\x83\xC0\x20"
        out += b"\x48\x89\x00"

        out += b"\x4D\x31\xC9"  # r9 = 0

        mark("fmt_loop")
        out += b"\x48\x31\xD2"
        out += b"\x48\xF7\xF3"
        out += b"\x48\x89\xC3"
        out += b"\x48\x83\xC2\x30"
        out += b"\x42\x88\x14\x08"
        out += b"\x49\xFF\xC1"
        out += b"\x48\x85\xDB"
        jrel(b"\x0F\x85\x00\x00\x00\x00", "fmt_loop")

        out += b"\x48\x85\xFF"
        jrel(b"\x0F\x84\x00\x00\x00\x00", "fmt_no_sign")
        out += b"\xC6\x04\x08\x2D"
        out += b"\x49\xFF\xC1"
        mark("fmt_no_sign")

        out += b"\xC6\x04\x08\x00"

        out += b"\x4C\x89\xC0"  # mov rax,r8

        out += b"\x41\x59"
        out += b"\x41\x58"
        out += b"\x5B"
        out += b"\xC3"

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

        # Patch fmt_heap LEA
        rip_after = fmt_heap_patch + 4
        rel = heap_ptr_offset - rip_after
        out[fmt_heap_patch:fmt_heap_patch+4] = self._i32(rel)

        return bytes(out), {
            "strlen": labels["__mantis_strlen"],
            "memcpy": labels["__mantis_memcpy"],
            "concat": labels["__mantis_string_concat"],
            "format_i64": labels["__mantis_format_i64"],
        }

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
        __mantis_format_i64
    plus a bump‑allocated heap appended after the code.

    build() returns (blob, offsets)
    """

    def build(self) -> tuple[bytes, dict[str, int]]:
        out = bytearray()
        labels = {}
        fixups = []

        def mark(name: str):
            labels[name] = len(out)

        def br(op: int, target: str):
            pos = len(out)
            out.extend(struct.pack("<I", op))
            fixups.append((pos, target, op))

        # ====================================================
        # __mantis_strlen
        # ====================================================
        mark("__mantis_strlen")
        out += struct.pack("<I", 0xAA0003E1)  # mov x1,x0

        mark("strlen_loop")
        out += struct.pack("<I", 0x39400022)  # ldrb w2,[x1]
        br(0x34000000, "strlen_done")        # cbz w2
        out += struct.pack("<I", 0x91000421) # add x1,x1,#1
        br(0x14000000, "strlen_loop")

        mark("strlen_done")
        out += struct.pack("<I", 0xCB000020) # sub x0,x1,x0
        out += struct.pack("<I", 0xD65F03C0) # ret

        # ====================================================
        # __mantis_memcpy
        # ====================================================
        mark("__mantis_memcpy")
        br(0xB4000000, "memcpy_done")        # cbz x2

        mark("memcpy_loop")
        out += struct.pack("<I", 0x39400023) # ldrb w3,[x1]
        out += struct.pack("<I", 0x39000003) # strb w3,[x0]
        out += struct.pack("<I", 0x91000421) # add x1,x1,#1
        out += struct.pack("<I", 0x91000400) # add x0,x0,#1
        out += struct.pack("<I", 0xD1000442) # sub x2,x2,#1
        br(0x35000000, "memcpy_loop")        # cbnz x2

        mark("memcpy_done")
        out += struct.pack("<I", 0xD65F03C0)

        # ====================================================
        # __mantis_string_concat
        # ====================================================
        mark("__mantis_string_concat")

        out += struct.pack("<I", 0xA9BF4FF3) # stp x19,x20,[sp,#-16]!
        out += struct.pack("<I", 0xA9BF57F5) # stp x21,x22,[sp,#-16]!

        out += struct.pack("<I", 0xAA0003F3) # mov x19,x0
        out += struct.pack("<I", 0xAA0103F4) # mov x20,x1

        # len_a
        out += struct.pack("<I", 0xAA1303E0)
        br(0x94000000, "__mantis_strlen")
        out += struct.pack("<I", 0xAA0003F5)

        # len_b
        out += struct.pack("<I", 0xAA1403E0)
        br(0x94000000, "__mantis_strlen")
        out += struct.pack("<I", 0xAA0003F6)

        out += struct.pack("<I", 0x8B1602B5) # add x21,x21,x22

        out += struct.pack("<I", 0xAA1503E2) # mov x2,x21
        out += struct.pack("<I", 0x91000442) # add x2,x2,#1

        mark("heap_ptr_adr")
        out += struct.pack("<I", 0x58000080)
        heap_ptr_patch = len(out)-4

        out += struct.pack("<I", 0xF9400001) # ldr x1,[x0]
        br(0x35000000, "heap_inited")

        out += struct.pack("<I", 0x91002001) # add x1,x0,#8
        out += struct.pack("<I", 0xF9000001) # str x1,[x0]

        mark("heap_inited")

        out += struct.pack("<I", 0xAA0103E3) # mov x3,x1

        out += struct.pack("<I", 0x8B020021) # add x1,x1,x2
        out += struct.pack("<I", 0xF9000001) # str x1,[x0]

        out += struct.pack("<I", 0xAA0303E0) # mov x0,x3

        # memcpy(result,a,len_a)
        out += struct.pack("<I", 0xAA0303E0)
        out += struct.pack("<I", 0xAA1303E1)
        out += struct.pack("<I", 0xAA1503E2)
        br(0x94000000, "__mantis_memcpy")

        # memcpy(result+len_a,b,len_b)
        out += struct.pack("<I", 0x8B150060)
        out += struct.pack("<I", 0xAA1403E1)
        out += struct.pack("<I", 0xAA1603E2)
        br(0x94000000, "__mantis_memcpy")

        out += struct.pack("<I", 0x3900001F) # strb wzr,[x0]

        out += struct.pack("<I", 0xA8C157F5)
        out += struct.pack("<I", 0xA8C14FF3)
        out += struct.pack("<I", 0xD65F03C0)

        # ====================================================
        # __mantis_format_i64
        # ====================================================
        mark("__mantis_format_i64")

        out += struct.pack("<I", 0xA9BF0FF3) # stp x19,x20,[sp,#-16]!
        out += struct.pack("<I", 0xAA0003F3) # mov x19,x0

        # abs + sign
