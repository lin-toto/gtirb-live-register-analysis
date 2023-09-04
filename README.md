# gtirb-live-register-analysis

## Overview

The gtirb-live-register-analysis package provides a Python API for live register analysis of GTIRB functions. 
A simple interface is also provided for working with [gtirb-rewriting](https://github.com/GrammaTech/gtirb-rewriting/) 
patches.

## Supported ABIs

| ISA          | File Format |
|--------------|-------------|
| X64 (x86-64) | ELF         |

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