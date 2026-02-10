# cli.py
# ============================================================
# Mantis 6 — High-Performance CLI
# ============================================================

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
from pathlib import Path

import compiler as mantis_compiler
import loader as mantis_loader

# ============================================================
# CONSTANTS
# ============================================================

MAGIC_MTNB = b"MTNB"
MTNB_HEADER = struct.Struct("<4sHHII")  # magic, version, reserved, module_count, asset_count
ENTRY_STRUCT = struct.Struct("<IIII")   # name_offset, name_len, data_offset, data_len

# ============================================================
# UTIL
# ============================================================

def _read(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


# ============================================================
# BUILD — SINGLE FILE
# ============================================================

def build_file(src: Path) -> Path:
    if src.suffix != ".mt":
        raise RuntimeError("build expects .mt file")

    code = src.read_text(encoding="utf-8")
    bytecode = mantis_compiler.compile_source(code)

    out = src.with_suffix(".mtn")
    _write(out, bytecode)

    return out


# ============================================================
# BUILD — PROJECT → FLAT MTNB
# ============================================================

def build_project(folder: Path) -> Path:
    modules: list[tuple[bytes, bytes]] = []
    assets: list[tuple[bytes, bytes]] = []

    # ---------- scan ----------
    for path in folder.rglob("*"):
        if path.suffix == ".mt":
            bc = mantis_compiler.compile_source(path.read_text("utf-8"))
            name = path.with_suffix(".mtn").name.encode()
            modules.append((name, bc))
        elif path.is_file():
            assets.append((path.name.encode(), _read(path)))

    module_count = len(modules)
    asset_count  = len(assets)

    # ---------- header ----------
    out = bytearray()
    out += MTNB_HEADER.pack(MAGIC_MTNB, 1, 0, module_count, asset_count)

    table_offset = len(out)

    # reserve tables for modules + assets
    out += b"\x00" * ENTRY_STRUCT.size * (module_count + asset_count)

    # ---------- payload ----------
    name_offsets = []
    data_offsets = []

    # names
    for name, _ in modules + assets:
        name_offsets.append(len(out))
        out += name

    # data
    for _, data in modules + assets:
        data_offsets.append(len(out))
        out += data

    # ---------- fill tables ----------
    cursor = table_offset
    for i, (name, data) in enumerate(modules + assets):
        entry = ENTRY_STRUCT.pack(
            name_offsets[i],
            len(name),
            data_offsets[i],
            len(data),
        )
        out[cursor:cursor + ENTRY_STRUCT.size] = entry
        cursor += ENTRY_STRUCT.size

    bundle_path = folder.with_suffix(".mtnb")
    _write(bundle_path, bytes(out))

    return bundle_path


# ============================================================
# RUN
# ============================================================

def run_path(path: Path) -> int:
    return mantis_loader.run(str(path))


# ============================================================
# BENCHMARK
# ============================================================

def bench_file(src: Path, iterations: int = 1000):
    start_compile = time.perf_counter()
    mtn = build_file(src)
    end_compile = time.perf_counter()

    start_run = time.perf_counter()
    result = 0
    for _ in range(iterations):
        result = run_path(mtn)
    end_run = time.perf_counter()

    print("Result:", result)
    print(f"Compile time : {(end_compile - start_compile)*1e3:.3f} ms")
    print(f"Run avg time : {(end_run - start_run)*1e6/iterations:.3f} µs")


# ============================================================
# CLI PARSER
# ============================================================

def _cmd_build(args):
    p = Path(args.path)

    if p.is_dir():
        out = build_project(p)
    else:
        out = build_file(p)

    print("Built:", out)


def _cmd_run(args):
    result = run_path(Path(args.path))
    print(result)


def _cmd_bench(args):
    bench_file(Path(args.path), args.iter)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="mantis", add_help=True)
    sub = parser.add_subparsers(dest="cmd", required=True)

    # build
    p_build = sub.add_parser("build")
    p_build.add_argument("path")
    p_build.set_defaults(func=_cmd_build)

    # run
    p_run = sub.add_parser("run")
    p_run.add_argument("path")
    p_run.set_defaults(func=_cmd_run)

    # bench
    p_bench = sub.add_parser("bench")
    p_bench.add_argument("path")
    p_bench.add_argument("--iter", type=int, default=1000)
    p_bench.set_defaults(func=_cmd_bench)

    args = parser.parse_args(argv)
    args.func(args)


# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":
    main()