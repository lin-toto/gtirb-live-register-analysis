from capstone import CsInsn

from .base import InstructionSemantics


_COMPARE_MNEMONICS = {"cmp", "cmn", "tst", "ccmp", "ccmn"}
_STORE_PREFIXES = ("str", "stp", "stur", "stlr", "stxr")


class AArch64InstructionSemantics(InstructionSemantics):
    def instruction_regs_read_fallback(self, instruction: CsInsn):
        if self._is_compare(instruction) or self._is_store(instruction) or self._is_test_branch(instruction):
            return self._all_operand_registers(instruction)
        return super().instruction_regs_read_fallback(instruction)

    def needs_explicit_read_fallback(self, instruction: CsInsn) -> bool:
        return (
            self._is_compare(instruction) or
            self._is_store(instruction) or
            self._is_test_branch(instruction)
        )

    def ignore_register_name(self, reg_name: str) -> bool:
        return reg_name is not None and reg_name.lower() in ("xzr", "wzr")

    @staticmethod
    def _is_compare(instruction: CsInsn) -> bool:
        return instruction.mnemonic in _COMPARE_MNEMONICS

    @staticmethod
    def _is_store(instruction: CsInsn) -> bool:
        return instruction.mnemonic.startswith(_STORE_PREFIXES)

    @staticmethod
    def _is_test_branch(instruction: CsInsn) -> bool:
        return instruction.mnemonic.startswith(("cb", "tb"))
