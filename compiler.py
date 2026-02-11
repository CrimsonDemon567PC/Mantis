from __future__ import annotations

import ast
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional

from linear_scan_allocator import Instr, allocate_registers


# ============================================================
# ISA OPCODES  (must match backends)
# ============================================================

OP_LOADI   = 0x01
OP_ADD     = 0x02
OP_SUB     = 0x03
OP_MUL     = 0x04
OP_DIV     = 0x05
OP_RET     = 0x06
OP_PRINT   = 0x20
OP_READLN  = 0x21


# ============================================================
# BYTECODE INSTRUCTION
# ============================================================

@dataclass
class BCInstr:
    op: int
    dst: int = 0
    src1: int = 0
    src2: int = 0
    imm: int = 0

    def encode(self) -> bytes:
        return struct.pack("<BBBBi", self.op, self.dst, self.src1, self.src2, self.imm)


# ============================================================
# IR BUILDER (AST → virtual register IR)
# ============================================================

class IRBuilder(ast.NodeVisitor):
    """
    Converts Python AST into a flat IR using virtual registers.
    """

    def __init__(self):
        self.instructions: List[Instr] = []
        self.constants: List[int] = []
        self.var_regs: Dict[str, int] = {}
        self.next_vreg = 0
        self.return_reg: Optional[int] = None

    # ---------- helpers ----------

    def new_reg(self) -> int:
        r = self.next_vreg
        self.next_vreg += 1
        return r

    def emit(self, op: int, dst=None, src1=None, src2=None):
        self.instructions.append(Instr(op, dst, src1, src2))

    # ---------- literals ----------

    def visit_Constant(self, node: ast.Constant):
        if not isinstance(node.value, int):
            raise TypeError("Only integer constants supported")

        r = self.new_reg()
        self.emit(OP_LOADI, r, None, None)
        self.constants.append(node.value)
        return r

    # ---------- variables ----------

    def visit_Name(self, node: ast.Name):
        if node.id not in self.var_regs:
            raise RuntimeError(f"Undefined variable {node.id}")
        return self.var_regs[node.id]

    # ---------- binary ops ----------

    def visit_BinOp(self, node: ast.BinOp):
        left = self.visit(node.left)
        right = self.visit(node.right)

        dst = self.new_reg()

        if isinstance(node.op, ast.Add):
            self.emit(OP_ADD, dst, left, right)
        elif isinstance(node.op, ast.Sub):
            self.emit(OP_SUB, dst, left, right)
        elif isinstance(node.op, ast.Mult):
            self.emit(OP_MUL, dst, left, right)
        elif isinstance(node.op, ast.Div):
            self.emit(OP_DIV, dst, left, right)
        else:
            raise NotImplementedError(type(node.op))

        return dst

    # ---------- assignment ----------

    def visit_Assign(self, node: ast.Assign):
        value_reg = self.visit(node.value)

        for target in node.targets:
            if not isinstance(target, ast.Name):
                raise NotImplementedError("Only simple assignments supported")

            self.var_regs[target.id] = value_reg

    # ---------- return ----------

    def visit_Return(self, node: ast.Return):
        if node.value is None:
            raise RuntimeError("Return value required")

        self.return_reg = self.visit(node.value)

    # ---------- print ----------

    def visit_Expr(self, node: ast.Expr):
        if isinstance(node.value, ast.Call):
            call = node.value

            if isinstance(call.func, ast.Name) and call.func.id == "print":
                if len(call.args) != 1:
                    raise RuntimeError("print expects one argument")

                r = self.visit(call.args[0])
                self.emit(OP_PRINT, r, None, None)
                return

        raise NotImplementedError("Unsupported expression")


# ============================================================
# SPILL-AWARE BYTECODE GENERATION
# ============================================================

def generate_bytecode(ir: IRBuilder) -> bytes:
    """
    Runs register allocation and converts IR into final bytecode.
    """

    alloc = allocate_registers(ir.instructions)

    bc: List[BCInstr] = []

    const_index = 0

    for ins in ir.instructions:
        dst = ins.dst
        src1 = ins.src1
        src2 = ins.src2

        # Resolve physical register indices
        def phys(v: Optional[int]) -> int:
            if v is None:
                return 0
            if v in alloc.vreg_to_phys:
                # Map register name → index
                return list(alloc.vreg_to_phys).index(v)
            return 0

        # LOADI needs constant
        if ins.op == OP_LOADI:
            imm = ir.constants[const_index]
            const_index += 1
            bc.append(BCInstr(OP_LOADI, phys(dst), 0, 0, imm))
            continue

        if ins.op in (OP_ADD, OP_SUB, OP_MUL, OP_DIV):
            bc.append(BCInstr(ins.op, phys(dst), phys(src1), phys(src2)))
            continue

        if ins.op == OP_PRINT:
            bc.append(BCInstr(OP_PRINT, phys(dst)))
            continue

    # ---------- return ----------
    if ir.return_reg is None:
        raise RuntimeError("Missing return statement")

    bc.append(BCInstr(OP_RET, phys(ir.return_reg)))

    return b"".join(i.encode() for i in bc)


# ============================================================
# PUBLIC API
# ============================================================

def compile_source(source: str) -> bytes:
    """
    Full compilation pipeline:

        Python source
            → AST
            → IR (virtual registers)
            → Linear-scan allocation
            → Spill-aware bytecode
    """

    tree = ast.parse(source)

    builder = IRBuilder()
    builder.visit(tree)

    return generate_bytecode(builder)