from dataclasses import dataclass
from gtirb_rewriting.abi import CallingConventionDesc, ABI, _X86_64_ELF as _X86_64_ELF_BASE
from gtirb_rewriting.assembly import Register
from typing import Set, List, Optional


class AnalysisAwareABI(ABI):
    def calling_convention_registers(self) -> Set[Register]:
        return {
            self.get_register(name)
            for name in self.calling_convention().registers
        }

    def callee_saved_registers(self) -> Set[Register]:
        return set(self.all_registers()).difference(self.caller_saved_registers())

    def return_registers(self) -> Set[Register]:
        raise NotImplementedError

    def flag_register(self) -> Optional[Register]:
        raise NotImplementedError


class _X86_64_ELF(_X86_64_ELF_BASE, AnalysisAwareABI):
    def all_registers(self) -> List[Register]:
        registers = super().all_registers() + [
            Register({"8l": "bpl", "16": "bp", "32": "ebp", "64": "rbp"}, "64"),
            Register({"8l": "spl", "16": "sp", "32": "esp", "64": "rsp"}, "64"),
            Register({"64": "rflags"}, "64")  # Add a fake RFLAGS register to allow its analysis
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
