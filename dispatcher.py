# ============================================================
# Mantis 7 Dispatcher — Builtins, String Runtime, Type Handling
# ============================================================

import os
import platform
import struct

# The loader will call set_string_blob() before execution.
STRING_BLOB = b""

def set_string_blob(blob: bytes):
    """
    Called by the loader to provide the string blob extracted
    from the .mtn or .mtnb bytecode.
    """
    global STRING_BLOB
    STRING_BLOB = blob


# ============================================================
# iOS Sandbox Detection
# ============================================================

def _is_ios_sandbox() -> bool:
    """
    Detect whether we are running inside an iOS sandbox
    (e.g. a-Shell on iPad/iPhone).
    Native write(1, ...) does not display output there.
    """
    m = platform.machine().lower()
    return m.startswith("ipad") or m.startswith("iphone") or m.startswith("ipod")

IOS_SANDBOX = _is_ios_sandbox()


# ============================================================
# Type Markers (Compiler uses these classes)
# ============================================================

class I64: pass
class F64: pass
class Bool: pass
class Str: pass


# ============================================================
# String Runtime
# ============================================================

def _load_string(ptr: int) -> str:
    """
    Load a null-terminated UTF-8 string from the global blob.
    """
    blob = STRING_BLOB
    end = blob.find(b"\x00", ptr)
    return blob[ptr:end].decode("utf-8")


# Runtime-created strings (concat, to_string)
RUNTIME_STRING_BLOB = bytearray()

def _intern_runtime_string(text: str) -> int:
    """
    Store a new UTF-8 string in the runtime string blob.
    Returns the pointer (offset).
    """
    data = text.encode("utf-8") + b"\x00"
    off = len(RUNTIME_STRING_BLOB)
    RUNTIME_STRING_BLOB.extend(data)
    return off


# ============================================================
# Builtin: print
# ============================================================

def _builtin_print(args, types):
    """
    Print values with correct type formatting.
    Uses native write(1, ...) except on iOS sandbox.
    """
    out_parts = []

    for val, t in zip(args, types):
        if t is Str:
            out_parts.append(_load_string(val))
        elif t is F64:
            f = struct.unpack("<d", struct.pack("<Q", val))[0]
            out_parts.append(str(f))
        elif t is Bool:
            out_parts.append("true" if val else "false")
        else:
            out_parts.append(str(val))

    s = " ".join(out_parts)

    if IOS_SANDBOX:
        print(s)
    else:
        os.write(1, s.encode("utf-8") + b"\n")

    return 0


# ============================================================
# Builtin: concat (string + string)
# ============================================================

def _builtin_concat(a_ptr: int, b_ptr: int) -> int:
    """
    Concatenate two strings and return a new pointer.
    """
    a = _load_string(a_ptr)
    b = _load_string(b_ptr)
    return _intern_runtime_string(a + b)


# ============================================================
# Builtin: to_string (convert any value to string)
# ============================================================

def _builtin_to_string(val, t) -> int:
    """
    Convert a typed value to a string and return pointer.
    """
    if t is Str:
        return val

    if t is Bool:
        return _intern_runtime_string("true" if val else "false")

    if t is F64:
        f = struct.unpack("<d", struct.pack("<Q", val))[0]
        return _intern_runtime_string(str(f))

    # Default: I64
    return _intern_runtime_string(str(val))


# ============================================================
# Builtin Dispatch Table
# ============================================================

def dispatch_builtin(fn_id: int, args, arg_types):
    """
    Called by the native backend when a builtin is invoked.
    fn_id:
        -1 = print
        -2 = concat
        -3 = to_string
    """
    if fn_id == -1:
        return _builtin_print(args, arg_types)

    if fn_id == -2:
        return _builtin_concat(args[0], args[1])

    if fn_id == -3:
        return _builtin_to_string(args[0], arg_types[0])

    raise RuntimeError(f"Unknown builtin ID: {fn_id}")
