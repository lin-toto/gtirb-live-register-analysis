from capstone import CsInsn
from gtirb_rewriting.assembly import Register


class InstructionSemantics:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    @property
    def abi(self):
        return self.analyzer.abi

    def instruction_regs_read_fallback(self, instruction: CsInsn):
        return self._operand_registers(instruction, list(instruction.operands)[1:])

    def instruction_regs_write_fallback(self, instruction: CsInsn):
        operands = list(instruction.operands)
        if not operands:
            return set()
        return self.analyzer._operand_registers(
            instruction, operands[0], include_memory_base=False)

    def instruction_regs_write_override(self, instruction: CsInsn):
        return None

    def ignore_register_name(self, reg_name: str) -> bool:
        return False

    def register_write_kills(self, reg: Register, reg_name: str) -> bool:
        return True

    def needs_explicit_read_fallback(self, instruction: CsInsn) -> bool:
        return False

    def _all_operand_registers(self, instruction: CsInsn):
        return self._operand_registers(instruction, instruction.operands)

    def _operand_registers(self, instruction: CsInsn, operands):
        registers = set()
        for operand in operands:
            registers.update(self.analyzer._operand_registers(instruction, operand))
        return registers

    def _register(self, name: str):
        return self.abi.get_register(name) if name in self.abi._register_map else None
