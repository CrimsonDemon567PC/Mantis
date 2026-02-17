# cli.py
# ============================================================
# Mantis 7 — Clean, Loader-Synced CLI
# ============================================================

from __future__ import annotations

import argparse
import time
from pathlib import Path

from . import compiler_core as mantis_compiler
from . import loader as mantis_loader


# ============================================================
# BUILD — SINGLE FILE (.mt → .mtn)
# ============================================================

def build_file(src: Path) -> Path:
    if src.suffix != ".mt":
        raise RuntimeError("build expects .mt file")

    code = src.read_text("utf-8")
    bytecode = mantis_compiler.compile_source(code)

    out = src.with_suffix(".mtn")
    out.write_bytes(bytecode)
    return out


# ============================================================
# BUILD — PROJECT (.mt → .mtnb)
# ============================================================

def build_project(folder: Path) -> Path:
    modules: list[tuple[str, bytes]] = []
    assets: list[tuple[str, bytes]] = []

    for path in folder.rglob("*"):
        if path.suffix == ".mt":
            bc = mantis_compiler.compile_source(path.read_text("utf-8"))
            name = path.with_suffix(".mtn").name
            modules.append((name, bc))
        elif path.is_file():
            assets.append((path.name, path.read_bytes()))

    # Build MTNB bundle
    out = bytearray()

    # Header: magic, version, reserved, module_count, asset_count
    out += b"MTNB"
    out += (1).to_bytes(2, "little")   # version
    out += (0).to_bytes(2, "little")   # reserved
    out += len(modules).to_bytes(4, "little")
    out += len(assets).to_bytes(4, "little")

    # Reserve table
    entry_size = 16
    table_offset = len(out)
    out += b"\x00" * entry_size * (len(modules) + len(assets))

    name_offsets = []
    data_offsets = []

    # Names
    for name, _ in modules + assets:
        name_offsets.append(len(out))
        out += name.encode()

    # Data
    for _, data in modules + assets:
        data_offsets.append(len(out))
        out += data

    # Fill table
    cursor = table_offset
    for i, (name, data) in enumerate(modules + assets):
        entry = (
            name_offsets[i].to_bytes(4, "little") +
            len(name).to_bytes(4, "little") +
            data_offsets[i].to_bytes(4, "little") +
            len(data).to_bytes(4, "little")
        )
        out[cursor:cursor+entry_size] = entry
        cursor += entry_size

    bundle_path = folder.with_suffix(".mtnb")
    bundle_path.write_bytes(out)
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
# CLI
# ============================================================

def main(argv=None):
    parser = argparse.ArgumentParser(prog="mantis", add_help=True)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build")
    p_build.add_argument("path")
    p_build.set_defaults(func=lambda a: print("Built:", build_file(Path(a.path))
                                             if Path(a.path).is_file()
                                             else build_project(Path(a.path))))

    p_run = sub.add_parser("run")
    p_run.add_argument("path")
    p_run.set_defaults(func=lambda a: print(run_path(Path(a.path))))

    p_bench = sub.add_parser("bench")
    p_bench.add_argument("path")
    p_bench.add_argument("--iter", type=int, default=1000)
    p_bench.set_defaults(func=lambda a: bench_file(Path(a.path), a.iter))

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
