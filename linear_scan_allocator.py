from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Optional


# ============================================================
# CONFIGURATION
# ============================================================

# Physical general-purpose registers available for allocation.
# RSP and RBP are excluded because they are reserved for
# stack pointer and frame pointer management.
PHYS_REGS = [
    "rax", "rbx", "rcx", "rdx",
    "rsi", "rdi",
    "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15",
]

# Size of one spilled stack slot in bytes.
STACK_SLOT_SIZE = 8


# ============================================================
# IR DATA STRUCTURES
# ============================================================

@dataclass
class Instr:
    """
    Minimal intermediate representation instruction used by the allocator.
    Only virtual register references are relevant here.
    """
    op: int
    dst: Optional[int]
    src1: Optional[int]
    src2: Optional[int]


@dataclass
class LiveInterval:
    """
    Represents the lifetime of a virtual register in instruction index space.
    """
    vreg: int
    start: int
    end: int
    phys: Optional[str] = None      # Assigned physical register
    stack: Optional[int] = None     # Stack slot offset if spilled


# ============================================================
# LIVENESS ANALYSIS
# ============================================================

def compute_live_intervals(instrs: List[Instr]) -> List[LiveInterval]:
    """
    Compute live intervals for all virtual registers.

    The start is the first instruction index where the register appears.
    The end   is the last instruction index where it appears.
    """

    first_use: Dict[int, int] = {}
    last_use: Dict[int, int] = {}

    for index, ins in enumerate(instrs):
        for v in (ins.dst, ins.src1, ins.src2):
            if v is None:
                continue

            if v not in first_use:
                first_use[v] = index
            last_use[v] = index

    intervals = [
        LiveInterval(vreg=v, start=first_use[v], end=last_use[v])
        for v in first_use
    ]

    # Linear scan requires intervals sorted by start position.
    intervals.sort(key=lambda iv: iv.start)
    return intervals


# ============================================================
# LINEAR SCAN REGISTER ALLOCATION
# ============================================================

def linear_scan_allocate(intervals: List[LiveInterval]) -> None:
    """
    Perform classic linear-scan register allocation.

    This function mutates the intervals in place by assigning either:
        - a physical register, or
        - a stack spill slot.
    """

    active: List[LiveInterval] = []        # Currently live intervals
    free_regs: List[str] = PHYS_REGS.copy()
    next_stack_offset = 0


    def expire_old_intervals(current: LiveInterval):
        """
        Remove intervals from the active set whose lifetime ended
        before the current interval starts. Freed registers return
        to the free register pool.
        """
        nonlocal active, free_regs

        still_active: List[LiveInterval] = []

        for iv in active:
            if iv.end >= current.start:
                still_active.append(iv)
            else:
                if iv.phys is not None:
                    free_regs.append(iv.phys)

        # Active list must stay sorted by end position.
        active = sorted(still_active, key=lambda iv: iv.end)


    for current in intervals:
        expire_old_intervals(current)

        # Case 1: A physical register is available.
        if free_regs:
            current.phys = free_regs.pop()
            active.append(current)
            active.sort(key=lambda iv: iv.end)
            continue

        # Case 2: No register available → spilling required.
        spill = active[-1]  # Interval with the farthest end.

        if spill.end > current.end:
            # Spill the active interval with the longer lifetime.
            current.phys = spill.phys

            spill.phys = None
            spill.stack = next_stack_offset
            next_stack_offset += STACK_SLOT_SIZE

            active[-1] = current
            active.sort(key=lambda iv: iv.end)
        else:
            # Spill the current interval instead.
            current.stack = next_stack_offset
            next_stack_offset += STACK_SLOT_SIZE


# ============================================================
# FINAL MAPPING CONSTRUCTION
# ============================================================

@dataclass
class AllocationResult:
    """
    Final allocation result used by the backend code generator.
    """
    vreg_to_phys: Dict[int, str]
    vreg_to_stack: Dict[int, int]
    stack_size: int


def build_allocation(intervals: List[LiveInterval]) -> AllocationResult:
    """
    Convert annotated intervals into a backend-friendly mapping.
    """

    vreg_to_phys: Dict[int, str] = {}
    vreg_to_stack: Dict[int, int] = {}
    max_stack_usage = 0

    for iv in intervals:
        if iv.phys is not None:
            vreg_to_phys[iv.vreg] = iv.phys
        elif iv.stack is not None:
            vreg_to_stack[iv.vreg] = iv.stack
            max_stack_usage = max(max_stack_usage, iv.stack + STACK_SLOT_SIZE)

    return AllocationResult(
        vreg_to_phys=vreg_to_phys,
        vreg_to_stack=vreg_to_stack,
        stack_size=max_stack_usage,
    )


# ============================================================
# PUBLIC ENTRY POINT
# ============================================================

def allocate_registers(instrs: List[Instr]) -> AllocationResult:
    """
    Full allocation pipeline:

        IR instructions
            → live interval computation
            → linear scan allocation
            → backend mapping result
    """

    intervals = compute_live_intervals(instrs)
    linear_scan_allocate(intervals)
    return build_allocation(intervals)