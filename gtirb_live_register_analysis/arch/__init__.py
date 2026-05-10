from .aarch64 import AArch64InstructionSemantics
from .base import InstructionSemantics
from .riscv64 import RISCV64InstructionSemantics
from .x64 import X64InstructionSemantics


def semantics_for_abi(analyzer) -> InstructionSemantics:
    arch = getattr(analyzer.abi, "analysis_arch", None)
    if arch == "riscv64":
        return RISCV64InstructionSemantics(analyzer)
    if arch == "aarch64":
        return AArch64InstructionSemantics(analyzer)
    if arch == "x64":
        return X64InstructionSemantics(analyzer)
    return InstructionSemantics(analyzer)


__all__ = [
    "AArch64InstructionSemantics",
    "InstructionSemantics",
    "RISCV64InstructionSemantics",
    "X64InstructionSemantics",
    "semantics_for_abi",
]
