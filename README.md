# MANTIS 7 COMPILER INFRASTRUCTURE
Mantis 7 is a high-performance native-compilation system that translates a Python-like source language into optimized machine code for x86-64 and ARM64 architectures.

## HOW IT WORKS

The Mantis 7 pipeline operates through several distinct stages:

### A. FRONTEND (compiler.py) 
The frontend uses the Python 'ast' module to parse source code. It performs type inference and lowers the AST into a custom Portable ISA (Instruction Set Architecture). This intermediate format uses a stable 4-byte magic header (MTN1) and a structured opcode format.

### B. REGISTER ALLOCATION 
(linear_scan_allocator.py) Before native code generation, the system uses a Linear Scan algorithm to map virtual registers (SSA temps) to physical CPU registers. If the available physical registers (8 on both x64 and ARM64) are exhausted, variables are "spilled" to stack slots.

### C. BACKENDS (backend_x64.py / backend_arm64.py) 
The portable opcodes are translated into native machine instructions.

- x64: Uses System V / Windows ABI, manual REX prefix encoding, and rax-centric arithmetic.

- ARM64: Uses AAPCS64 ABI, mapping operations to AArch64 registers x0-x7 with proper frame pointer management.

### D. LOADING & EXECUTION (loader.py)
The loader allocates executable memory (RWX) using VirtualAlloc (Windows) or mmap (POSIX). It maps the compiled code into this memory and executes it as a native function pointer via ctypes.

## SYNTAX GUIDE

Mantis 7 supports a subset of Python syntax optimized for performance:

- TYPES: i64 (Integer), f64 (Float), Bool.

- VARIABLES: Explicit assignment; the compiler handles local stack allocation.

- ARITHMETIC: Standard operators (+, -, *, /) and comparisons (==, <, >).

## CONTROL FLOW:

- 'if' / 'else' blocks.

- 'while' loops.

- 'for i in range(n)' loops.

## FUNCTIONS:

- Defined with 'def'.

- Support for recursion.

- Uses standard ABI calling conventions for native performance.

- DATA STRUCTURES: Classes (static dispatch) and Arrays.

## USAGE

The system is managed via the 'cli.py' tool.

### A. BUILDING A FILE 
To compile a source file (.mt) into portable bytecode (.mtn): python cli.py build path/to/source.mt

### B. RUNNING A FILE 
To compile and immediately execute a file natively: python cli.py run path/to/source.mt

### C. BENCHMARKING 
To measure compilation and execution performance: python cli.py bench path/to/source.mt --iter 1000

### D. BUNDLING 
Mantis supports .mtnb files, which are production-ready bundles containing multiple modules and assets in a zero-copy format.
