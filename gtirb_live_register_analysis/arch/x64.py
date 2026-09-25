from capstone import CsInsn
from capstone.x86_const import (
    X86_INS_ADC, X86_INS_ADD, X86_INS_CMP, X86_INS_NEG, X86_INS_SBB, X86_INS_SUB,
)

from .base import InstructionSemantics


_EXPLICIT_READ_MNEMONICS = {"adox", "test"}
_FULL_ARITHMETIC_FLAGS_WRITERS = {
    X86_INS_ADC, X86_INS_ADD, X86_INS_CMP, X86_INS_NEG, X86_INS_SBB, X86_INS_SUB,
}


class X64InstructionSemantics(InstructionSemantics):
    def instruction_regs_read_fallback(self, instruction: CsInsn):
        if instruction.mnemonic in _EXPLICIT_READ_MNEMONICS:
            return self._all_operand_registers(instruction)
        return super().instruction_regs_read_fallback(instruction)

    def needs_explicit_read_fallback(self, instruction: CsInsn) -> bool:
        # Capstone 5 marks ADOX's destination as write-only even though its
        # previous value is an input to the addition.  Preserve that value in
        # liveness independently of the decoder version in use.
        # TEST's register operand can also be omitted in memory-first forms.
        return instruction.mnemonic in _EXPLICIT_READ_MNEMONICS

    def instruction_regs_write_override(self, instruction: CsInsn):
        if instruction.mnemonic.startswith("cmov") or instruction.mnemonic == "test":
            # TEST never writes a GPR; its flag write is not a complete kill
            # of the tracked arithmetic flags (AF is undefined).
            return set()
        return None

    def register_write_kills(self, instruction: CsInsn, reg, reg_name: str) -> bool:
        if reg == self.abi.flag_register():
            # The tracked value is CF/PF/AF/ZF/SF/OF, not DF or full RFLAGS.
            # These instructions define all six unconditionally; ADC/SBB's
            # incoming carry remains a read in the liveness transfer. Keep
            # partial/conditional writes and undefined outputs conservative.
            # Instruction IDs also cover prefixed forms such as LOCK ADD.
            return instruction.id in _FULL_ARITHMETIC_FLAGS_WRITERS
        return self.analyzer._register_access_size(reg, reg_name) > 16
