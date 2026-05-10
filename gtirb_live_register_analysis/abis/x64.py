from typing import List, Optional, Set

from gtirb_rewriting.abi import CallingConventionDesc, _X86_64_ELF as _X86_64_ELF_BASE
from gtirb_rewriting.assembly import Register

from .base import AnalysisAwareABI


class _X86_64_ELF(_X86_64_ELF_BASE, AnalysisAwareABI):
    analysis_arch = "x64"

    def all_registers(self) -> List[Register]:
        registers = super().all_registers() + [
            Register({"8l": "bpl", "16": "bp", "32": "ebp", "64": "rbp"}, "64"),
            Register({"8l": "spl", "16": "sp", "32": "esp", "64": "rsp"}, "64"),
            Register({"64": "rflags"}, "64"),
        ]

        for i in range(0, 31):
            registers.append(Register({
                "128": f"xmm{i}", "256": f"ymm{i}", "512": f"zmm{i}"
            }, default_size="128"))

        return registers

    def _scratch_registers(self) -> List[Register]:
        return super().all_registers()

    def calling_convention(self) -> CallingConventionDesc:
        calling_convention = super().calling_convention()
        calling_convention.registers += tuple(f"xmm{i}" for i in range(0, 8))
        return calling_convention

    def caller_saved_registers(self) -> Set[Register]:
        return super().caller_saved_registers().union({self.get_register("RFLAGS")})

    def return_registers(self) -> Set[Register]:
        return {
            self.get_register(name)
            for name in ("RAX", "RDX")
        }

    def flag_register(self) -> Optional[Register]:
        return self.get_register("RFLAGS")
