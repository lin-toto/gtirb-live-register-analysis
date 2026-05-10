from typing import List, Optional, Set

from gtirb_rewriting.abi import CallingConventionDesc, _AsmSnippet
from gtirb_rewriting.assembly import Register

from .base import AnalysisAwareABI


class _RISCV64_ELF(AnalysisAwareABI):
    analysis_arch = "riscv64"

    _REGISTER_ALIASES = (
        (0, "zero"),
        (1, "ra"),
        (2, "sp"),
        (3, "gp"),
        (4, "tp"),
        (5, "t0"),
        (6, "t1"),
        (7, "t2"),
        (8, "s0"),
        (9, "s1"),
        (10, "a0"),
        (11, "a1"),
        (12, "a2"),
        (13, "a3"),
        (14, "a4"),
        (15, "a5"),
        (16, "a6"),
        (17, "a7"),
        (18, "s2"),
        (19, "s3"),
        (20, "s4"),
        (21, "s5"),
        (22, "s6"),
        (23, "s7"),
        (24, "s8"),
        (25, "s9"),
        (26, "s10"),
        (27, "s11"),
        (28, "t3"),
        (29, "t4"),
        (30, "t5"),
        (31, "t6"),
    )

    def _register_names(self, idx: int, abi_name: str):
        return {"64": abi_name, "64_alt": f"x{idx}"}

    def all_registers(self) -> List[Register]:
        return [
            Register(self._register_names(idx, abi_name), "64")
            for idx, abi_name in self._REGISTER_ALIASES
        ]

    def nop(self) -> bytes:
        return b"\x13\x00\x00\x00"

    def _scratch_registers(self) -> List[Register]:
        return [
            self.get_register(name)
            for name in (
                "t0", "t1", "t2", "t3", "t4", "t5", "t6",
                "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
            )
        ]

    def _create_prologue_and_epilogue(self, constraints, register_use, is_leaf_function):
        if constraints.clobbers_flags:
            constraints.clobbers_flags = False

        registers = list(register_use.clobbered_registers)
        stack_adjustment = ((len(registers) * 8 + 15) // 16) * 16
        if stack_adjustment == 0:
            return [], [], 0

        prologue = [_AsmSnippet(f"addi sp, sp, -{stack_adjustment}")]
        epilogue = []
        for idx, reg in enumerate(registers):
            offset = idx * 8
            prologue.append(_AsmSnippet(f"sd {reg}, {offset}(sp)"))
            epilogue.append(_AsmSnippet(f"ld {reg}, {offset}(sp)"))
        epilogue.append(_AsmSnippet(f"addi sp, sp, {stack_adjustment}"))

        return prologue, epilogue, stack_adjustment

    def caller_saved_registers(self) -> Set[Register]:
        return {
            self.get_register(name)
            for name in (
                "ra",
                "t0", "t1", "t2", "t3", "t4", "t5", "t6",
                "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
            )
        }

    def pointer_size(self) -> int:
        return 8

    def calling_convention(self) -> CallingConventionDesc:
        return CallingConventionDesc(
            registers=("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
            stack_alignment=16,
            caller_cleanup=True,
        )

    def stack_register(self) -> Register:
        return self.get_register("sp")

    def temporary_label_prefix(self) -> str:
        return ".L"

    def default_dwarf_eh_return_column(self) -> int:
        return 1

    def return_registers(self) -> Set[Register]:
        return {self.get_register(name) for name in ("a0", "a1")}

    def flag_register(self) -> Optional[Register]:
        return None

    def is_call_instruction(self, instruction) -> bool:
        return instruction.mnemonic in ("call", "tail", "jal", "jalr", "c.jal", "c.jalr")
