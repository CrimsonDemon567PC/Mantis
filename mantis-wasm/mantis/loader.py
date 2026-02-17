# loader.py
# ============================================================
# Mantis 7 Loader — Production Zero-Copy Native Loader
# ABI 1.0 compliant
# ============================================================

from __future__ import annotations

import os
import mmap
import ctypes
import struct
import platform

from backend_x64 import emit_x64
from backend_arm64 import emit_arm64
from string_runtime import StringRuntimeX64, StringRuntimeARM64


def _extract_string_blob(bytecode: memoryview) -> bytes:
    """
    Extract the string blob from a raw .mtn bytecode buffer.
    Layout:
        [magic 4]
        [fn_count u32]
        per function:
            [code_len u32]
            repeated:
                [op u8][a i32][b i32][c i32]
        [string_blob_size u32]
        [string_blob raw]
    """
    off = 0

    # Skip magic
    off += 4

    # Read fn_count
    fn_count = struct.unpack_from("<I", bytecode, off)[0]
    off += 4

    # Skip all function bodies
    for _ in range(fn_count):
        code_len = struct.unpack_from("<I", bytecode, off)[0]
        off += 4 + code_len * 13   # each instruction = 13 bytes

    # Read blob size
    blob_size = struct.unpack_from("<I", bytecode, off)[0]
    off += 4

    # Extract blob
    blob = bytecode[off : off + blob_size].tobytes()
    return blob


# ============================================================
# CONSTANT STRUCTS (ABI 1.0)
# ============================================================

MTNB_HEADER = struct.Struct("<4sHHII")
ENTRY_STRUCT = struct.Struct("<IIII")

MAGIC = b"MTNB"
SUPPORTED_VERSION = 1


# ============================================================
# EXECUTABLE MEMORY (cross-platform)
# ============================================================

def _alloc_exec(size: int):
    """
    Allocate RWX memory in a cross-platform safe way.
    """

    if os.name == "nt":
        # Windows VirtualAlloc
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualAlloc.restype = ctypes.c_void_p

        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40

        ptr = kernel32.VirtualAlloc(
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        if not ptr:
            raise MemoryError("VirtualAlloc failed")

        return ptr

    # POSIX mmap
    prot = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
    mm = mmap.mmap(-1, size, prot=prot)
    buf = (ctypes.c_char * size).from_buffer(mm)
    return ctypes.addressof(buf), mm


# ============================================================
# ARCH DETECTION
# ============================================================

def _detect_arch() -> str:
    m = platform.machine().lower()

    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("arm64", "aarch64"):
        return "arm64"

    raise RuntimeError(f"Unsupported architecture: {m}")


ARCH = _detect_arch()


# ============================================================
# SAFE MMAP FILE
# ============================================================

class MMapFile:
    def __init__(self, path: str):
        self.path = path
        self.fd = None
        self.mm: mmap.mmap | None = None
        self.size = 0

    def open(self):
        self.size = os.path.getsize(self.path)
        self.fd = os.open(self.path, os.O_RDONLY)
        self.mm = mmap.mmap(self.fd, self.size, access=mmap.ACCESS_READ)
        os.close(self.fd)

    def close(self):
        if self.mm:
            self.mm.close()
            self.mm = None

    # -------- bounds-checked slice --------
    def slice(self, off: int, length: int) -> memoryview:
        if off < 0 or length < 0 or off + length > self.size:
            raise RuntimeError("Out-of-bounds access in MTNB")
        return memoryview(self.mm)[off : off + length]


# ============================================================
# PARSED STRUCTURES
# ============================================================

class Module:
    __slots__ = ("name", "data")

    def __init__(self, name: str, data: memoryview):
        self.name = name
        self.data = data


class Asset:
    __slots__ = ("name", "data")

    def __init__(self, name: str, data: memoryview):
        self.name = name
        self.data = data


# ============================================================
# MTNB PARSER (strict & safe)
# ============================================================

class Bundle:
    def __init__(self, mm: MMapFile):
        self.mm = mm
        self.modules: list[Module] = []
        self.assets: list[Asset] = []

    # -------------------------
    # HEADER
    # -------------------------
    def _parse_header(self):
        raw = self.mm.slice(0, MTNB_HEADER.size)
        magic, version, _reserved, mcount, acount = MTNB_HEADER.unpack(raw)

        if magic != MAGIC:
            raise RuntimeError("Invalid MTNB magic")

        if version != SUPPORTED_VERSION:
            raise RuntimeError(f"Unsupported MTNB version {version}")

        return mcount, acount

    # -------------------------
    # TABLES
    # -------------------------
    def _parse_tables(self, mcount: int, acount: int):
        offset = MTNB_HEADER.size

        # ---------- modules ----------
        for _ in range(mcount):
            raw = self.mm.slice(offset, ENTRY_STRUCT.size)
            name_off, name_len, data_off, data_len = ENTRY_STRUCT.unpack(raw)

            name = self.mm.slice(name_off, name_len).tobytes().decode("utf-8")
            data = self.mm.slice(data_off, data_len)

            self.modules.append(Module(name, data))
            offset += ENTRY_STRUCT.size

        # ---------- assets ----------
        for _ in range(acount):
            raw = self.mm.slice(offset, ENTRY_STRUCT.size)
            name_off, name_len, data_off, data_len = ENTRY_STRUCT.unpack(raw)

            name = self.mm.slice(name_off, name_len).tobytes().decode("utf-8")
            data = self.mm.slice(data_off, data_len)

            self.assets.append(Asset(name, data))
            offset += ENTRY_STRUCT.size

    # -------------------------
    # PUBLIC PARSE
    # -------------------------
    def parse(self):
        mcount, acount = self._parse_header()
        self._parse_tables(mcount, acount)

    # -------------------------
    # ENTRY LOOKUP
    # -------------------------
    def find_module(self, name: str) -> Module:
        for m in self.modules:
            if m.name == name:
                return m
        raise RuntimeError(f"Module not found: {name}")


# ============================================================
# NATIVE EXECUTION
# ============================================================

def _translate(bytecode: memoryview) -> bytes:
    """
    Dispatch portable ISA → native machine code and append
    the architecture-specific string runtime blob.
    """

    code_bytes = bytecode.tobytes()

    if ARCH == "x64":
        runtime_blob, rt_offsets = StringRuntimeX64().build()
        native = emit_x64(code_bytes, rt_offsets)
        return native + runtime_blob

    if ARCH == "arm64":
        runtime_blob, rt_offsets = StringRuntimeARM64().build()
        native = emit_arm64(code_bytes, rt_offsets)
        return native + runtime_blob

    raise RuntimeError("No backend for architecture")


def _execute(native: bytes) -> int:
    """
    Execute native code buffer and return int64 result.
    """

    size = len(native)

    if os.name == "nt":
        ptr = _alloc_exec(size)
        ctypes.memmove(ptr, native, size)
        func = ctypes.CFUNCTYPE(ctypes.c_int64)(ptr)
        return func()

    # POSIX mmap path
    ptr, mm = _alloc_exec(size)
    ctypes.memmove(ptr, native, size)
    func = ctypes.CFUNCTYPE(ctypes.c_int64)(ptr)
    result = func()
    mm.close()
    return result


# ============================================================
# PUBLIC RUN API
# ============================================================

def run(path: str) -> int:
    """
    Execute .mtn or .mtnb
    """

    # --------------------------------------------------------
    # Raw .mtn file (single module)
    # --------------------------------------------------------
    if path.endswith(".mtn"):
        with open(path, "rb") as f:
            bytecode = f.read()

        # Extract string blob from raw bytecode
        blob = _extract_string_blob(memoryview(bytecode))

        # Provide blob to dispatcher (still used by higher-level facilities)
        import dispatcher
        dispatcher.set_string_blob(blob)

        # Translate and execute
        native = _translate(memoryview(bytecode))
        return _execute(native)

    # --------------------------------------------------------
    # .mtnb bundle (multiple modules)
    # --------------------------------------------------------
    if path.endswith(".mtnb"):
        mm = MMapFile(path)
        mm.open()

        bundle = Bundle(mm)
        bundle.parse()

        # Load the main module
        main = bundle.find_module("main.mtn")
        bytecode = main.data

        # Extract string blob from the module bytecode
        blob = _extract_string_blob(bytecode)

        # Provide blob to dispatcher
        import dispatcher
        dispatcher.set_string_blob(blob)

        # Translate and execute
        native = _translate(bytecode)
        result = _execute(native)

        mm.close()
        return result

    # --------------------------------------------------------
    # Unsupported file type
    # --------------------------------------------------------
    raise RuntimeError("Unsupported file type")


from dispatcher import *
