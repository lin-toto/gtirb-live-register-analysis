from typing import List, Optional, Set

import gtirb_rewriting.abi as rewriting_abi
from gtirb_rewriting.assembly import Register

from .base import AnalysisAwareABI


_ARM64_ELF_BASE = (
    getattr(rewriting_abi, "_ARM64_ELF", None) or
    getattr(rewriting_abi, "_AARCH64_ELF", None) or
    getattr(rewriting_abi, "_AArch64_ELF", None)
)


class _ARM64_ELF(_ARM64_ELF_BASE, AnalysisAwareABI):
    analysis_arch = "aarch64"

    def all_registers(self) -> List[Register]:
        registers = [
            Register({"32": f"w{i}", "64": f"x{i}"}, "64")
            for i in range(31)
        ]
        registers.extend([
            Register({"32": "wsp", "64": "sp"}, "64"),
            Register({"64": "nzcv"}, "64"),
        ])
        return registers

    def _scratch_registers(self) -> List[Register]:
        return [
            self.get_register(f"x{i}")
            for i in range(18)
        ]

    def caller_saved_registers(self) -> Set[Register]:
        return {
            self.get_register(name)
            for name in (
                *(f"x{i}" for i in range(19)),
                "x30",
                "nzcv",
            )
        }

    def calling_convention_registers(self) -> Set[Register]:
        return {
            self.get_register(f"x{i}")
            for i in range(9)
        }

    def return_registers(self) -> Set[Register]:
        return {
            self.get_register(name)
            for name in ("x0", "x1")
        }

    def flag_register(self) -> Optional[Register]:
        return self.get_register("nzcv")

    def is_call_instruction(self, instruction) -> bool:
        return instruction.mnemonic in ("bl", "blr")


_AARCH64_ELF = _ARM64_ELF
