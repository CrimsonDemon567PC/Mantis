# ============================================================
# Mantis 7 — Linear Scan Register Allocator (Production)
# Updated for Float + String support
# ============================================================

from __future__ import annotations
from typing import List, Dict, Tuple

# ================= CPU REGISTER POOLS =================
# Caller-save registers only (safe for expression evaluation)

X86_64_REGS = [
    0,  # rax
    3,  # rbx
    1,  # rcx
    2,  # rdx
    8, 9, 10, 11  # r8-r11
]

ARM64_REGS = list(range(0, 8))  # x0-x7 (caller-save)


# ================= SSA TEMP =================

class Temp:
    __slots__ = ("name", "start", "end", "reg", "stack_slot", "is_arg")

    def __init__(self, name: str, start: int, end: int, is_arg=False):
        self.name = name
        self.start = start
        self.end = end
        self.reg = None
        self.stack_slot = None
        self.is_arg = is_arg  # NEW: mark temps used as CALL arguments


# ================= LIVE INTERVAL =================

class LiveInterval:
    __slots__ = ("temp", "start", "end")

    def __init__(self, temp: Temp):
        self.temp = temp
        self.start = temp.start
        self.end = temp.end


# ================= LINEAR SCAN ALLOCATOR =================

class LinearScanAllocator:
    def __init__(self, temps: List[Temp], arch: str):
        self.temps = sorted(temps, key=lambda t: t.start)
        self.arch = arch
        self.active: List[LiveInterval] = []

        if arch == "x86_64":
            self.reg_pool = X86_64_REGS.copy()
        elif arch == "arm64":
            self.reg_pool = ARM64_REGS.copy()
        else:
            raise RuntimeError(f"Unsupported arch {arch}")

        self.stack_slots: List[Temp] = []
        self.next_stack_offset = 0  # in bytes

    # --------------------------------------------------------
    # Main allocation
    # --------------------------------------------------------
    def allocate(self):
        for temp in self.temps:
            self.expire_old_intervals(temp)

            # CALL arguments must be in ABI registers
            if temp.is_arg:
                if self.reg_pool:
                    temp.reg = self.reg_pool.pop(0)
                else:
                    temp.stack_slot = self._alloc_stack()
                continue

            # Normal allocation
            if self.reg_pool:
                reg = self.reg_pool.pop(0)
                temp.reg = reg
                self.active.append(LiveInterval(temp))
                self.active.sort(key=lambda x: x.end)
            else:
                temp.stack_slot = self._alloc_stack()

    # --------------------------------------------------------
    # Expire intervals
    # --------------------------------------------------------
    def expire_old_intervals(self, temp: Temp):
        new_active = []
        for interval in self.active:
            if interval.end >= temp.start:
                new_active.append(interval)
            else:
                # free register
                if interval.temp.reg is not None:
                    self.reg_pool.append(interval.temp.reg)
        self.active = new_active

    # --------------------------------------------------------
    # Allocate stack slot
    # --------------------------------------------------------
    def _alloc_stack(self):
        slot = self.next_stack_offset
        self.next_stack_offset += 8  # 64-bit slot
        return slot

    # --------------------------------------------------------
    # Public API
    # --------------------------------------------------------
    def get_mapping(self) -> Dict[str, Tuple[int, int]]:
        mapping = {}
        for temp in self.temps:
            mapping[temp.name] = (temp.reg, temp.stack_slot)
        return mapping

    def get_stack_size(self) -> int:
        return self.next_stack_offset
