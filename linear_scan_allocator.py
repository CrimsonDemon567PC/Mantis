# ============================================================
# Mantis 7 — Linear Scan Register Allocator (Production)
# Maps SSA temps to CPU registers or stack slots
# Fully integrated, no placeholders, no examples
# ============================================================

from __future__ import annotations
from typing import List, Dict, Tuple

# ================= CPU REGISTER POOLS =================

X86_64_REGS = [0, 1, 2, 3, 8, 9, 10, 11]  # rax, rbx, rcx, rdx, r8-r11 (caller-save)
ARM64_REGS  = list(range(0, 8))           # x0-x7 (argument / caller-save)

# ================= SSA TEMP =================

class Temp:
    __slots__ = ("name", "start", "end", "reg", "stack_slot")

    def __init__(self, name: str, start: int, end: int):
        self.name = name
        self.start = start
        self.end = end
        self.reg = None
        self.stack_slot = None

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

    def allocate(self):
        """
        Main linear scan allocation.
        Assigns CPU registers or stack slots to SSA temps.
        """
        for temp in self.temps:
            self.expire_old_intervals(temp)
            if self.reg_pool:
                # assign first available register
                reg = self.reg_pool.pop(0)
                temp.reg = reg
                self.active.append(LiveInterval(temp))
                self.active.sort(key=lambda x: x.end)
            else:
                # spill to stack
                temp.stack_slot = self.next_stack_offset
                self.next_stack_offset += 8  # 64-bit slot
                self.stack_slots.append(temp)

    def expire_old_intervals(self, temp: Temp):
        """
        Free registers of intervals that ended before `temp.start`.
        """
        new_active = []
        for interval in self.active:
            if interval.end >= temp.start:
                new_active.append(interval)
            else:
                # free the register
                if interval.temp.reg is not None:
                    self.reg_pool.append(interval.temp.reg)
        self.active = new_active

    def get_mapping(self) -> Dict[str, Tuple[int, int]]:
        """
        Returns mapping of temp_name -> (reg, stack_slot)
        If a temp has a register, stack_slot is None.
        """
        mapping = {}
        for temp in self.temps:
            mapping[temp.name] = (temp.reg, temp.stack_slot)
        return mapping

    def get_stack_size(self) -> int:
        """
        Returns total bytes of stack needed for spills.
        """
        return self.next_stack_offset