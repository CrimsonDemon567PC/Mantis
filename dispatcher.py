# dispatcher.py
# ============================================================
# Mantis Builtin Dispatcher — drop-in, no core changes needed
# ============================================================

import ctypes
import struct
import loader

# ------------------------------------------------------------
# Builtin registry
# ------------------------------------------------------------

BUILTINS = {}

def _builtin_concat(a_ptr, b_ptr):
    a = _load_string(a_ptr)
    b = _load_string(b_ptr)
    s = (a + b).encode("utf-8") + b"\x00"
    off = len(STRING_BLOB)
    STRING_BLOB.extend(s)
    return off

def _builtin_to_string(val, type):
    if type is I64:
        return _intern_runtime_string(str(val))
    if type is F64:
        return _intern_runtime_string(str(val))
    if type is Bool:
        return _intern_runtime_string("true" if val else "false")
    raise TypeError("Cannot convert to string")


def builtin_print(args):
    # args = list of Python ints (string pointers)
    # We need to resolve string pointers from the MTN string blob.
    if not hasattr(loader, "_current_string_blob"):
        print("[mantis:print] <no string blob>")
        return 0

    blob = loader._current_string_blob
    out = []

    for ptr in args:
        if ptr < 0 or ptr >= len(blob):
            out.append(f"<bad_ptr:{ptr}>")
            continue

        # read until null terminator
        s = []
        i = ptr
        while i < len(blob) and blob[i] != 0:
            s.append(chr(blob[i]))
            i += 1

        out.append("".join(s))

    print(*out)
    return 0

BUILTINS[-1] = builtin_print


# ------------------------------------------------------------
# Patch loader._execute to intercept builtin calls
# ------------------------------------------------------------

_original_execute = loader._execute

def _execute_patched(native):
    """
    Intercepts builtin calls encoded in the native buffer.
    We detect a builtin trampoline marker and call Python instead.
    """

    # Builtin trampoline convention:
    # If native == b"BUILTIN\x00" + struct.pack("<i", id)
    # then we call BUILTINS[id]
    if native.startswith(b"BUILTIN\x00"):
        bid = struct.unpack("<i", native[8:12])[0]
        fn = BUILTINS.get(bid)
        if fn is None:
            raise RuntimeError(f"Unknown builtin id {bid}")
        return fn([])

    return _original_execute(native)

loader._execute = _execute_patched


# ------------------------------------------------------------
# Patch loader._translate to emit builtin trampolines
# ------------------------------------------------------------

_original_translate = loader._translate

def _translate_patched(bytecode):
    """
    If the bytecode contains OP_CALL -1, we replace the native code
    with a builtin trampoline instead of real machine code.
    """

    # Extract string blob for print()
    # Format: [magic][fn_count][...functions...][blob_size][blob]
    data = bytecode.tobytes()
    magic = data[:4]
    if magic == b"MTN1":
        # find string blob
        # skip functions
        pos = 4
        fn_count = struct.unpack_from("<I", data, pos)[0]
        pos += 4

        for _ in range(fn_count):
            clen = struct.unpack_from("<I", data, pos)[0]
            pos += 4 + clen * 13

        blob_size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        loader._current_string_blob = data[pos:pos+blob_size]

    # detect builtin call
    # naive v1: if any OP_CALL has a == -1, treat whole function as builtin
    pos = 4
    fn_count = struct.unpack_from("<I", data, pos)[0]
    pos += 4

    for _ in range(fn_count):
        clen = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        for i in range(clen):
            op, a, b, c = struct.unpack_from("<Biii", data, pos)
            pos += 13
            if op == 8 and a == -1:  # OP_CALL, builtin
                # return trampoline
                return b"BUILTIN\x00" + struct.pack("<i", -1)

    # fallback to real native translation
    return _original_translate(bytecode)

loader._translate = _translate_patched
