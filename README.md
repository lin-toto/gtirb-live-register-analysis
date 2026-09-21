# gtirb-live-register-analysis

## Overview

The gtirb-live-register-analysis package provides a Python API for live register analysis of GTIRB functions. 
A simple interface is also provided for working with [gtirb-rewriting](https://github.com/GrammaTech/gtirb-rewriting/) 
patches.

## Supported ABIs

| ISA          | File Format |
|--------------|-------------|
| ARM64        | ELF         |
| RISCV64      | ELF         |
| X64 (x86-64) | ELF         |

The x64 `rflags` value tracks the six arithmetic flags (CF/PF/AF/ZF/SF/OF), not
DF or other control flags. ADD, SUB, CMP, NEG, ADC and SBB completely define
that value; ADC/SBB still require their incoming carry. Partial writes, shifts
and instructions with undefined outputs remain conservative. Consumers must
preserve DF and other non-arithmetic flags independently if they modify them.

## Ddisasm Metadata

When present, `LiveRegisterManager` consumes interprocedural liveness results
from two module AuxData tables:

| Name | Type | Meaning |
|------|------|---------|
| `liveRegisterNames` | `sequence<string>` | Register name for each mask bit. |
| `liveRegisterSets` | `mapping<Offset,uint64_t>` | Live-in mask at each instruction offset. |

Both tables are validated before use. Offsets are relative to CodeBlocks.
Missing tables or incompatible schemas/register names fall back to Python
analysis with a warning naming the module, analysis scope and reason. Invalid
individual entries are removed with a warning; valid entries remain usable.
A missing instruction entry is treated as all registers live, without running
Python analysis. Structural validation does not prove that an instruction's
register effects still match the frontend analysis.

After rewriting, call `reg_manager.refresh()` before analyzing or allocating
again. By default, an unspecified edit invalidates all old module masks with a
warning. Changed uses can propagate into predecessors and callers; dropping
only the changed instruction's entry is not sufficient. The now-missing entries
are all-live, without running Python analysis.

Use `refresh(preserve_liveness=True)` only when the transformation preserves the
original register dependencies and control-flow meaning. It reloads migrated
tables and clears decoded instructions and per-round added-live state. The
rewriter must move offsets for surviving instructions and remove entries for
replacements/deletions. Copies need independent offset maps. This explicit
contract does not infer equivalence of arbitrary edits or automatically detect
in-place mutations that a caller fails to declare.
Use `analysis_scope="block"` for a fallback with all registers live at each
block exit, including unresolved successors.

## Getting Started

### Generic Usage

```python
from gtirb_live_register_analysis import LiveRegisterManager

reg_manager = LiveRegisterManager(module)

# Analyze function of interest
reg_manager.analyze(function)

# The sets of live and free registers can then be retrieved
live_regs = reg_manager.live_registers(function, block, instruction_idx)
free_regs = reg_manager.free_registers(function, block, instruction_idx)
```

### Use with gtirb-rewriting patches

Wrap the decorator function around a patch function to assign free registers to be used as scratch registers.
When there are not enough free registers, the library falls back to gtirb-rewriting, which generates code to
spill/restore the excess registers to stack.

```python
@reg_manager.allocate_registers(function, block, instruction_idx)
@patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=6)
def my_patch(self, ctx: InsertionContext):
    reg1, reg2, reg3, reg4, reg5, reg6 = ctx.scratch_registers
    return f"""
        xor {reg1}, {reg1}
        xor {reg2}, {reg2}
        xor {reg3}, {reg3}
        xor {reg4}, {reg4}
        xor {reg5}, {reg5}
        xor {reg6}, {reg6}
    """

rewriting_ctx.insert_at(block, offset, Patch.from_function(my_patch))
```
