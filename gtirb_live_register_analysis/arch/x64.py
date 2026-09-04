from capstone import CsInsn

from .base import InstructionSemantics


_READ_WRITE_OPERAND0_MNEMONICS = {"adox"}


class X64InstructionSemantics(InstructionSemantics):
    def instruction_regs_read_fallback(self, instruction: CsInsn):
        if instruction.mnemonic in _READ_WRITE_OPERAND0_MNEMONICS:
            return self._all_operand_registers(instruction)
        return super().instruction_regs_read_fallback(instruction)

    def needs_explicit_read_fallback(self, instruction: CsInsn) -> bool:
        # Capstone 5 marks ADOX's destination as write-only even though its
        # previous value is an input to the addition.  Preserve that value in
        # liveness independently of the decoder version in use.
        return instruction.mnemonic in _READ_WRITE_OPERAND0_MNEMONICS

    def instruction_regs_write_override(self, instruction: CsInsn):
        if instruction.mnemonic.startswith("cmov"):
            return set()
        return None

    def register_write_kills(self, reg, reg_name: str) -> bool:
        return self.analyzer._register_access_size(reg, reg_name) > 16
