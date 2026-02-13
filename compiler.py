# ============================================================
# Mantis 7 Compiler — Core Frontend, Types, Symbols, AST Lowering
# ============================================================

from __future__ import annotations
import ast
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ============================================================
# BYTECODE CONSTANTS
# ============================================================

MAGIC_MTN = b"MTN1"

# Opcodes (stable ISA v1)
OP_CONST_I64 = 1
OP_CONST_F64 = 2
OP_ADD = 3
OP_SUB = 4
OP_MUL = 5
OP_DIV = 6
OP_RETURN = 7
OP_CALL = 8
OP_LOAD = 9
OP_STORE = 10
OP_ALLOC_STACK = 11
OP_FIELD_LOAD = 12
OP_FIELD_STORE = 13
OP_JMP = 14
OP_JMP_IF_FALSE = 15
OP_CMP_EQ = 16
OP_CMP_LT = 17
OP_CMP_GT = 18

# ============================================================
# TYPE SYSTEM
# ============================================================

class Type:
    size: int
    align: int

@dataclass
class I64(Type):
    size: int = 8
    align: int = 8

@dataclass
class F64(Type):
    size: int = 8
    align: int = 8

@dataclass
class Bool(Type):
    size: int = 1
    align: int = 1

@dataclass
class Str(Type):
    size: int = 16
    align: int = 8

@dataclass
class Array(Type):
    elem: Type = None
    size: int = 16
    align: int = 8

@dataclass
class StructType(Type):
    name: str = ""
    fields: Dict[str, Type] = field(default_factory=dict)
    offsets: Dict[str, int] = field(default_factory=dict)
    size: int = 0
    align: int = 8

# ============================================================
# SYMBOL TABLE
# ============================================================

class Symbol:
    name: str
    type: Type

@dataclass
class VarSymbol(Symbol):
    name: str
    type: Type
    slot: int

@dataclass
class FuncSymbol(Symbol):
    name: str
    params: List[Type]
    ret: Type
    addr: int = 0

@dataclass
class ClassSymbol(Symbol):
    name: str
    type: StructType
    methods: Dict[str, FuncSymbol] = field(default_factory=dict)

# ============================================================
# SCOPE
# ============================================================

class Scope:
    def __init__(self, parent: Optional[Scope] = None):
        self.parent = parent
        self.symbols: Dict[str, Symbol] = {}

    def define(self, sym: Symbol):
        self.symbols[sym.name] = sym

    def resolve(self, name: str) -> Symbol:
        if name in self.symbols:
            return self.symbols[name]
        if self.parent:
            return self.parent.resolve(name)
        raise NameError(name)

# ============================================================
# IR INSTRUCTION
# ============================================================

@dataclass
class Instr:
    op: int
    a: int = 0
    b: int = 0
    c: int = 0

# ============================================================
# FUNCTION CONTEXT
# ============================================================

class FunctionCtx:
    def __init__(self, scope: Scope):
        self.scope = scope
        self.code: List[Instr] = []
        self.stack_size = 0

    def emit(self, op, a=0, b=0, c=0):
        self.code.append(Instr(op, a, b, c))
        return len(self.code) - 1

    def alloc(self, t: Type) -> int:
        slot = self.stack_size
        self.stack_size += t.size
        return slot

# ============================================================
# COMPILER CORE
# ============================================================

class Compiler(ast.NodeVisitor):

    def __init__(self):
        self.globals = Scope()
        self.functions: List[FunctionCtx] = []
        self.current: Optional[FunctionCtx] = None
        self.classes: Dict[str, ClassSymbol] = {}

    # --------------------------------------------------------
    # ENTRY
    # --------------------------------------------------------

    def compile(self, source: str) -> bytes:
        tree = ast.parse(source)
        self.visit(tree)
        return self._emit_bytecode()

    # --------------------------------------------------------
    # MODULE
    # --------------------------------------------------------

    def visit_Module(self, node: ast.Module):
        for stmt in node.body:
            self.visit(stmt)

# ============================================================
# ASSIGNMENT
# ============================================================

def visit_Assign(self, node: ast.Assign):
    """
    Handle:
        x = expr
        obj.field = expr
    """
    assert len(node.targets) == 1
    target = node.targets[0]

    value_type = self.visit(node.value)

    # Local variable assignment
    if isinstance(target, ast.Name):
        try:
            sym = self.current.scope.resolve(target.id)
        except NameError:
            # New local variable
            slot = self.current.alloc(value_type)
            sym = VarSymbol(target.id, value_type, slot)
            self.current.scope.define(sym)

        self.current.emit(OP_STORE, sym.slot)
        return value_type

    # Struct field assignment: obj.field = value
    if isinstance(target, ast.Attribute):
        obj_type = self.visit(target.value)
        assert isinstance(obj_type, StructType)

        field_off = obj_type.offsets[target.attr]
        self.current.emit(OP_FIELD_STORE, field_off)
        return value_type

    raise NotImplementedError(type(target))


# ============================================================
# FUNCTION CALLS
# ============================================================

def visit_Call(self, node: ast.Call):
    """
    Unified call handler:
    - builtin print(...)
    - method calls: obj.method(...)
    - normal function calls
    """

    # ----------------------------------------
    # BUILTIN: print(...)
    # ----------------------------------------
    if isinstance(node.func, ast.Name) and node.func.id == "print":
        arg_types = []
        for arg in node.args:
            t = self.visit(arg)
            arg_types.append(t)

        # builtin print = -1
        self.current.emit(OP_CALL, -1, len(node.args))
        return I64()

    # ----------------------------------------
    # METHOD CALL: obj.method(...)
    # ----------------------------------------
    if isinstance(node.func, ast.Attribute):
        obj_type = self.visit(node.func.value)

        # push arguments
        for arg in node.args:
            self.visit(arg)

        return self._emit_method_call(obj_type, node.func.attr, len(node.args) + 1)

    # ----------------------------------------
    # NORMAL FUNCTION CALL
    # ----------------------------------------
    if isinstance(node.func, ast.Name):
        fn: FuncSymbol = self.globals.resolve(node.func.id)

        for arg in node.args:
            self.visit(arg)

        self.current.emit(OP_CALL, fn.addr, len(node.args))
        return fn.ret

    raise NotImplementedError("Unsupported call type")


# ============================================================
# IF STATEMENT
# ============================================================

def visit_If(self, node: ast.If):
    self.visit(node.test)

    jmp_false = self.current.emit(OP_JMP_IF_FALSE, 0)

    # then-block
    for stmt in node.body:
        self.visit(stmt)

    jmp_end = self.current.emit(OP_JMP, 0)

    # patch false jump
    self.current.code[jmp_false].a = len(self.current.code)

    # else-block
    for stmt in node.orelse:
        self.visit(stmt)

    # patch end
    self.current.code[jmp_end].a = len(self.current.code)


# ============================================================
# WHILE LOOP
# ============================================================

def visit_While(self, node: ast.While):
    start = len(self.current.code)

    self.visit(node.test)
    jmp_false = self.current.emit(OP_JMP_IF_FALSE, 0)

    for stmt in node.body:
        self.visit(stmt)

    self.current.emit(OP_JMP, start)

    # patch exit
    self.current.code[jmp_false].a = len(self.current.code)


# ============================================================
# COMPARISONS
# ============================================================

def visit_Compare(self, node: ast.Compare):
    """
    Only supports:
        a == b
        a < b
        a > b
    """
    assert len(node.ops) == 1
    assert len(node.comparators) == 1

    self.visit(node.left)
    self.visit(node.comparators[0])

    op = node.ops[0]

    if isinstance(op, ast.Eq):
        self.current.emit(OP_CMP_EQ)
    elif isinstance(op, ast.Lt):
        self.current.emit(OP_CMP_LT)
    elif isinstance(op, ast.Gt):
        self.current.emit(OP_CMP_GT)
    else:
        raise NotImplementedError(type(op))

    return Bool()


# ============================================================
# CLASS DEFINITIONS
# ============================================================

def visit_ClassDef(self, node: ast.ClassDef):
    """
    Class → StructType + method table
    """
    struct = StructType(name=node.name)

    offset = 0

    # Field declarations via annotations
    for stmt in node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            t = I64()  # v1: fixed field type
            struct.fields[stmt.target.id] = t
            struct.offsets[stmt.target.id] = offset
            offset += t.size

    struct.size = offset

    cls = ClassSymbol(node.name, struct)
    self.classes[node.name] = cls
    self.globals.define(cls)

    # Compile methods
    for stmt in node.body:
        if isinstance(stmt, ast.FunctionDef):
            self._compile_method(cls, stmt)


def _compile_method(self, cls: ClassSymbol, node: ast.FunctionDef):
    """
    Compile a method:
        def foo(self, x):
            ...
    """
    fn_scope = Scope(self.globals)
    ctx = FunctionCtx(fn_scope)

    self.functions.append(ctx)
    prev = self.current
    self.current = ctx

    # First param = self
    self_type = cls.type
    slot = ctx.alloc(self_type)
    fn_scope.define(VarSymbol("self", self_type, slot))

    # Other params
    for arg in node.args.args[1:]:
        t = I64()
        slot = ctx.alloc(t)
        fn_scope.define(VarSymbol(arg.arg, t, slot))

    # Body
    for stmt in node.body:
        self.visit(stmt)

    # Register method
    cls.methods[node.name] = FuncSymbol(
        node.name,
        [],
        I64(),
        addr=len(self.functions) - 1
    )

    self.current = prev


# ============================================================
# ATTRIBUTE LOAD
# ============================================================

def visit_Attribute(self, node: ast.Attribute):
    obj_type = self.visit(node.value)
    assert isinstance(obj_type, StructType)

    off = obj_type.offsets[node.attr]
    self.current.emit(OP_FIELD_LOAD, off)
    return obj_type.fields[node.attr]


# ============================================================
# ARRAY LITERAL
# ============================================================

def visit_List(self, node: ast.List):
    """
    Lower Python list literal → Mantis Array
    """
    length = len(node.elts)

    arr_type = Array(I64())
    slot = self.current.alloc(arr_type)

    # Store length
    self.current.emit(OP_CONST_I64, length)
    self.current.emit(OP_STORE, slot)

    # Store elements
    data_slot = slot + 8
    for i, elt in enumerate(node.elts):
        self.visit(elt)
        self.current.emit(OP_STORE, data_slot + i * 8)

    return arr_type

# ============================================================
# STRING LITERALS
# ============================================================

def visit_Constant_str(self, value: str):
    """
    Compile a string literal by interning it into the compile-time
    string blob and pushing its pointer.
    """
    encoded = value.encode("utf-8")
    ptr = self._intern_string(encoded)
    self.current.emit(OP_CONST_I64, ptr)
    return Str()


def _intern_string(self, data: bytes) -> int:
    """
    Store a UTF-8 string in the compile-time string blob.
    Returns the pointer (offset).
    """
    if not hasattr(self, "_strings"):
        self._strings = {}
        self._string_blob = bytearray()

    if data in self._strings:
        return self._strings[data]

    off = len(self._string_blob)
    self._string_blob += data + b"\x00"
    self._strings[data] = off
    return off


# ============================================================
# CONSTANT OVERRIDE (int, float, str)
# ============================================================

def visit_Constant(self, node: ast.Constant):
    """
    Extended constant handler:
    - int → I64
    - float → F64
    - str → Str (interned)
    """
    if isinstance(node.value, str):
        return self.visit_Constant_str(node.value)

    if isinstance(node.value, int):
        self.current.emit(OP_CONST_I64, node.value)
        return I64()

    if isinstance(node.value, float):
        bits = struct.unpack("<Q", struct.pack("<d", node.value))[0]
        self.current.emit(OP_CONST_F64, bits)
        return F64()

    raise TypeError("Unsupported constant type")


# ============================================================
# F-STRING SUPPORT (JoinedStr, FormattedValue)
# ============================================================

def visit_JoinedStr(self, node: ast.JoinedStr):
    """
    Compile an f-string by concatenating constant segments and
    formatted expressions. Uses builtin:
        -2 = concat
        -3 = to_string
    """

    # Start with an empty string
    empty_ptr = self._intern_string(b"")
    self.current.emit(OP_CONST_I64, empty_ptr)
    result_type = Str()

    for part in node.values:

        # Constant string segment
        if isinstance(part, ast.Constant):
            ptr = self._intern_string(part.value.encode("utf-8"))
            self.current.emit(OP_CONST_I64, ptr)
            self.current.emit(OP_CALL, -2, 2)  # concat
            continue

        # {expression}
        if isinstance(part, ast.FormattedValue):
            t = self.visit(part.value)
            self.current.emit(OP_CALL, -3, 1)  # to_string
            self.current.emit(OP_CALL, -2, 2)  # concat
            continue

        raise NotImplementedError(type(part))

    return result_type


def visit_FormattedValue(self, node: ast.FormattedValue):
    """
    Should never be called directly; JoinedStr handles it.
    """
    return self.visit(node.value)


# ============================================================
# CONSTANT FOLDING FOR BINARY OPS
# ============================================================

def visit_BinOp(self, node: ast.BinOp):
    """
    Compile-time constant folding for:
        +, -, *, //
    """

    if isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
        a = node.left.value
        b = node.right.value

        if isinstance(node.op, ast.Add):
            return self.visit(ast.Constant(a + b))
        if isinstance(node.op, ast.Sub):
            return self.visit(ast.Constant(a - b))
        if isinstance(node.op, ast.Mult):
            return self.visit(ast.Constant(a * b))
        if isinstance(node.op, ast.Div):
            return self.visit(ast.Constant(a // b))

    # fallback to normal lowering
    return super(Compiler, self).visit_BinOp(node)


# ============================================================
# GLOBAL VARIABLES
# ============================================================

def visit_AnnAssign(self, node: ast.AnnAssign):
    """
    Global variable with annotation:
        x: int = 5
    """
    assert isinstance(node.target, ast.Name)

    value_type = self.visit(node.value) if node.value else I64()

    slot = len(getattr(self, "_globals_mem", [])) * 8
    self._globals_mem = getattr(self, "_globals_mem", [])
    self._globals_mem.append(0)

    sym = VarSymbol(node.target.id, value_type, slot)
    self.globals.define(sym)


# ============================================================
# FOR LOOP (range only)
# ============================================================

def visit_For(self, node: ast.For):
    """
    Lower:
        for i in range(a, b):
            ...
    """

    assert isinstance(node.target, ast.Name)
    assert isinstance(node.iter, ast.Call)
    assert isinstance(node.iter.func, ast.Name)
    assert node.iter.func.id == "range"

    args = node.iter.args
    if len(args) == 1:
        start_node = ast.Constant(0)
        end_node = args[0]
    else:
        start_node, end_node = args

    # init i = start
    start_type = self.visit(start_node)
    slot = self.current.alloc(start_type)
    self.current.scope.define(VarSymbol(node.target.id, start_type, slot))
    self.current.emit(OP_STORE, slot)

    loop_start = len(self.current.code)

    # compare i < end
    self.current.emit(OP_LOAD, slot)
    self.visit(end_node)
    self.current.emit(OP_CMP_LT)

    jmp_false = self.current.emit(OP_JMP_IF_FALSE, 0)

    # body
    for stmt in node.body:
        self.visit(stmt)

    # i += 1
    self.current.emit(OP_LOAD, slot)
    self.current.emit(OP_CONST_I64, 1)
    self.current.emit(OP_ADD)
    self.current.emit(OP_STORE, slot)

    self.current.emit(OP_JMP, loop_start)

    # patch exit
    self.current.code[jmp_false].a = len(self.current.code)

# ============================================================
# DEAD CODE ELIMINATION (after return)
# ============================================================

def _strip_dead_code(self, ctx: FunctionCtx):
    """
    Remove all instructions after the first OP_RETURN.
    Simple but effective for v1.
    """
    new_code = []
    for ins in ctx.code:
        new_code.append(ins)
        if ins.op == OP_RETURN:
            break
    ctx.code = new_code


# ============================================================
# FINAL BYTECODE EMISSION (Loader-Ready)
# ============================================================

def _emit_bytecode(self) -> bytes:
    """
    Final MTN layout:

        [magic 4]
        [fn_count u32]

        per function:
            [code_len u32]
            repeated:
                [op u8][a i32][b i32][c i32]

        [string_blob_size u32]
        [string_blob raw]
    """

    out = bytearray()
    out += MAGIC_MTN

    # Optimize functions
    for fn in self.functions:
        self._strip_dead_code(fn)

    # Emit function table
    out += struct.pack("<I", len(self.functions))

    for fn in self.functions:
        out += struct.pack("<I", len(fn.code))
        for ins in fn.code:
            out += struct.pack("<Biii", ins.op, ins.a, ins.b, ins.c)

    # Emit string blob
    blob = getattr(self, "_string_blob", b"")
    out += struct.pack("<I", len(blob))
    out += blob

    return bytes(out)


# ============================================================
# BIND VISITORS TO COMPILER
# ============================================================

Compiler.visit_Assign = visit_Assign
Compiler.visit_Call = visit_Call
Compiler.visit_If = visit_If
Compiler.visit_While = visit_While
Compiler.visit_Compare = visit_Compare
Compiler.visit_ClassDef = visit_ClassDef
Compiler._compile_method = _compile_method
Compiler.visit_Attribute = visit_Attribute
Compiler.visit_List = visit_List

Compiler.visit_Constant_str = visit_Constant_str
Compiler._intern_string = _intern_string
Compiler.visit_Constant = visit_Constant

Compiler.visit_AnnAssign = visit_AnnAssign
Compiler.visit_For = visit_For
Compiler.visit_BinOp = visit_BinOp

Compiler.visit_JoinedStr = visit_JoinedStr
Compiler.visit_FormattedValue = visit_FormattedValue

Compiler._strip_dead_code = _strip_dead_code
Compiler._emit_bytecode = _emit_bytecode
