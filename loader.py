# loader.py
# ============================================================
# Mantis 6 Loader — Full Production, Zero-Copy, Typed ISA
# ============================================================

import os
import sys
import mmap
import ctypes
import platform
import struct

from backend_x64 import emit_x64
from backend_arm64 import emit_arm64

# -------------------------
# Header Structures
# -------------------------
MTNB_HEADER_STRUCT = struct.Struct("<4sHHII")  # magic, version, reserved, module_count, asset_count
MODULE_ENTRY_STRUCT = struct.Struct("<IIII")  # name_offset, name_len, data_offset, data_len
ASSET_ENTRY_STRUCT  = struct.Struct("<IIII")  # same

class ModuleEntry:
    def __init__(self, name_offset, name_len, data_offset, data_len):
        self.name_offset = name_offset
        self.name_len = name_len
        self.data_offset = data_offset
        self.data_len = data_len
        self.name = None
        self.data = None

class AssetEntry:
    def __init__(self, name_offset, name_len, data_offset, data_len):
        self.name_offset = name_offset
        self.name_len = name_len
        self.data_offset = data_offset
        self.data_len = data_len
        self.name = None
        self.data = None

# -------------------------
# Loader
# -------------------------
class MantisLoader:
    def __init__(self, path: str):
        self.path = path
        self.mm = None
        self.header = None
        self.modules = []
        self.assets = []
        self.arch = self.detect_arch()

    def detect_arch(self):
        arch = platform.machine().lower()
        if arch in ("x86_64", "amd64"):
            return "x86_64"
        elif arch in ("aarch64","arm64"):
            return "arm64"
        else:
            raise RuntimeError(f"Unsupported arch: {arch}")

    def map_file(self):
        size = os.path.getsize(self.path)
        fd = os.open(self.path, os.O_RDONLY)
        self.mm = mmap.mmap(fd, size, access=mmap.ACCESS_READ)
        os.close(fd)

    def parse_header(self):
        raw = self.mm[:MTNB_HEADER_STRUCT.size]
        magic, version, reserved, module_count, asset_count = MTNB_HEADER_STRUCT.unpack(raw)
        if magic != b"MTNB":
            raise RuntimeError("Invalid Mantis bundle")
        self.header = {
            "version": version,
            "reserved": reserved,
            "module_count": module_count,
            "asset_count": asset_count
        }

    def parse_tables(self):
        offset = MTNB_HEADER_STRUCT.size
        # Parse Module Entries
        self.modules = []
        for _ in range(self.header["module_count"]):
            raw = self.mm[offset:offset+MODULE_ENTRY_STRUCT.size]
            name_off, name_len, data_off, data_len = MODULE_ENTRY_STRUCT.unpack(raw)
            entry = ModuleEntry(name_off, name_len, data_off, data_len)
            entry.name = self.mm[name_off:name_off+name_len].decode("utf-8")
            entry.data = self.mm[data_off:data_off+data_len]
            self.modules.append(entry)
            offset += MODULE_ENTRY_STRUCT.size
        # Parse Asset Entries
        self.assets = []
        for _ in range(self.header["asset_count"]):
            raw = self.mm[offset:offset+ASSET_ENTRY_STRUCT.size]
            name_off, name_len, data_off, data_len = ASSET_ENTRY_STRUCT.unpack(raw)
            entry = AssetEntry(name_off, name_len, data_off, data_len)
            entry.name = self.mm[name_off:name_off+name_len].decode("utf-8")
            entry.data = self.mm[data_off:data_off+data_len]
            self.assets.append(entry)
            offset += ASSET_ENTRY_STRUCT.size

    def find_entry(self, name="main.mtn"):
        for m in self.modules:
            if m.name == name:
                return m
        raise RuntimeError(f"Entry module {name} not found")

    def execute_module(self, module_entry: ModuleEntry):
        # Compile to native depending on arch
        if self.arch == "x86_64":
            native = emit_x64(module_entry.data)
        elif self.arch == "arm64":
            native = emit_arm64(module_entry.data)
        # Map executable memory
        size = len(native)
        mm = mmap.mmap(-1, size, prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
        mm.write(native)
        buf = (ctypes.c_char * size).from_buffer(mm)
        func = ctypes.CFUNCTYPE(ctypes.c_int64)(ctypes.addressof(buf))
        result = func()
        mm.close()
        return result

    def run(self):
        self.map_file()
        self.parse_header()
        self.parse_tables()
        entry = self.find_entry("main.mtn")
        return self.execute_module(entry)