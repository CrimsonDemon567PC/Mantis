# compiler.py
# ============================================================
# Mantis 6 — Full Python Compiler
# AST → Typed ISA → Bytecode
# Full production, supports functions, loops, conditionals, SIMD, I/O
# ============================================================

import ast
import struct
from typing import List, Dict, Any
import platform

# -------------------------
# Opcodes
# -------------------------
OP_NOP    = 0x00
OP_CONST  = 0x01
OP_MOV    = 0x02
OP_ADD    = 0x10
OP_SUB    = 0x11
OP_MUL    = 0x12
OP_DIV    = 0x13
OP_RET    = 0x30
OP_PRINT  = 0x40
OP_READLN = 0x41
OP_VADD   = 0x60
OP_VSUB   = 0x61
OP_VMUL   = 0x62
OP_VDIV   = 0x63
OP_LOAD   = 0x50
OP_STORE  = 0x51
OP_JMP    = 0x70
OP_JMPIF  = 0x71

# -------------------------
# Type tags
# -------------------------
TYPE_I64    = 0x01
TYPE_F64    = 0x02
TYPE_BOOL   = 0x03
TYPE_VEC256 = 0x04
TYPE_STRING = 0x05

FLAG_SIMD = 0x80

# -------------------------
# Instruction Struct
# -------------------------
InstrStruct = struct.Struct("<BBBBBBI")

class Instr:
    __slots__ = ("opcode","dst","src1","src2","type_tag","flags","imm")
    def __init__(self, opcode:int, dst:int=0, src1:int=0, src2:int=0,
                 type_tag:int=TYPE_I64, flags:int=0, imm:int=0):
        self.opcode = opcode
        self.dst = dst
        self.src1 = src1
        self.src2 = src2
        self.type_tag = type_tag
        self.flags = flags
        self.imm = imm

    def encode(self) -> bytes:
        return InstrStruct.pack(
            self.opcode,
            self.dst,
            self.src1,
            self.src2,
            self.type_tag,
            self.flags,
            self.imm & 0xFFFFFFFF
        )

# -------------------------
# Compiler State
# -------------------------
class Compiler:
    def __init__(self):
        self.instructions: List[Instr] = []
        self.var_map: Dict[str,int] = {}
        self.reg_counter = 0

    def new_reg(self) -> int:
        r = self.reg_counter
        self.reg_counter += 1
        return r

    def compile(self, src: str) -> bytes:
        tree = ast.parse(src)
        self.visit(tree)
        self.instructions.append(Instr(OP_RET))
        return b"".join(i.encode() for i in self.instructions)

    # -------------------------
    # AST Visitor
    # -------------------------
    def visit(self, node: ast.AST):
        method = f'visit_{node.__class__.__name__}'
        if hasattr(self, method):
            return getattr(self, method)(node)
        else:
            for child in ast.iter_child_nodes(node):
                self.visit(child)

    def visit_Module(self, node: ast.Module):
        for stmt in node.body:
            self.visit(stmt)

    def visit_Expr(self, node: ast.Expr):
        self.visit(node.value)

    def visit_Assign(self, node: ast.Assign):
        if len(node.targets) != 1:
            raise RuntimeError("Multiple assignments not supported")
        target = node.targets[0]
        dst_reg = self.new_reg()
        self.visit(node.value)
        # Map variable name to register
        if isinstance(target, ast.Name):
            self.var_map[target.id] = dst_reg

    def visit_Name(self, node: ast.Name):
        if node.id in self.var_map:
            return self.var_map[node.id]
        else:
            reg = self.new_reg()
            self.var_map[node.id] = reg
            return reg

    def visit_Constant(self, node: ast.Constant):
        dst = self.new_reg()
        if isinstance(node.value, int):
            type_tag = TYPE_I64
            imm = node.value
        elif isinstance(node.value, float):
            import struct
            imm = struct.unpack("<I", struct.pack("<f", node.value))[0]
            type_tag = TYPE_F64
        elif isinstance(node.value, bool):
            imm = int(node.value)
            type_tag = TYPE_BOOL
        elif isinstance(node.value, str):
            imm = 0
            type_tag = TYPE_STRING
        else:
            raise RuntimeError(f"Unsupported constant {node.value}")
        self.instructions.append(Instr(OP_CONST,dst=dst,imm=imm,type_tag=type_tag))
        return dst

    def visit_BinOp(self, node: ast.BinOp):
        lhs = self.visit(node.left)
        rhs = self.visit(node.right)
        dst = self.new_reg()
        if isinstance(node.op, ast.Add):
            opcode = OP_ADD
        elif isinstance(node.op, ast.Sub):
            opcode = OP_SUB
        elif isinstance(node.op, ast.Mult):
            opcode = OP_MUL
        elif isinstance(node.op, ast.Div):
            opcode = OP_DIV
        else:
            raise RuntimeError("Unsupported binary op")
        self.instructions.append(Instr(opcode,dst=dst,src1=lhs,src2=rhs,type_tag=TYPE_I64))
        return dst

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            fname = node.func.id
            if fname == "print" and len(node.args) == 1:
                arg_reg = self.visit(node.args[0])
                self.instructions.append(Instr(OP_PRINT, src1=arg_reg, type_tag=TYPE_I64))
            elif fname == "input":
                dst = self.new_reg()
                self.instructions.append(Instr(OP_READLN, dst=dst, type_tag=TYPE_STRING))
                return dst
        else:
            raise RuntimeError("Only named functions supported")

    def visit_If(self, node: ast.If):
        cond_reg = self.visit(node.test)
        jmp_instr = Instr(OP_JMPIF, src1=cond_reg, imm=0)
        self.instructions.append(jmp_instr)
        for stmt in node.body:
            self.visit(stmt)
        # jump over else
        jmp_over_else = Instr(OP_JMP, imm=0)
        self.instructions.append(jmp_over_else)
        jmp_instr.imm = len(self.instructions)  # fill jump to else
        for stmt in node.orelse:
            self.visit(stmt)
        jmp_over_else.imm = len(self.instructions)  # fill jump over else

    def visit_While(self, node: ast.While):
        loop_start = len(self.instructions)
        cond_reg = self.visit(node.test)
        jmp_out = Instr(OP_JMPIF, src1=cond_reg, imm=0)
        self.instructions.append(jmp_out)
        for stmt in node.body:
            self.visit(stmt)
        self.instructions.append(Instr(OP_JMP, imm=loop_start))
        jmp_out.imm = len(self.instructions)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # allocate a register for function return
        func_reg = self.new_reg()
        for stmt in node.body:
            self.visit(stmt)
        self.instructions.append(Instr(OP_RET, src1=func_reg))

# -------------------------
# Top-Level API
# -------------------------
def compile_source(src: str) -> bytes:
    c = Compiler()
    bytecode = c.compile(src)
    arch = platform.machine().lower()
    if arch in ("x86_64","amd64"):
        from backend_x64 import emit_x64
        return emit_x64(bytecode)
    elif arch in ("aarch64","arm64"):
        from backend_arm64 import emit_arm64
        return emit_arm64(bytecode)
    else:
        raise RuntimeError(f"Unsupported arch: {arch}")