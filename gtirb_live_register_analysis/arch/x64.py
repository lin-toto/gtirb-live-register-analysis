from capstone import CsInsn

from .base import InstructionSemantics


class X64InstructionSemantics(InstructionSemantics):
    def instruction_regs_write_override(self, instruction: CsInsn):
        if instruction.mnemonic.startswith("cmov"):
            return set()
        return None

    def register_write_kills(self, reg, reg_name: str) -> bool:
        return self.analyzer._register_access_size(reg, reg_name) > 16
