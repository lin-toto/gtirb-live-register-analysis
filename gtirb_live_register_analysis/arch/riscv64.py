from capstone import CS_OP_REG, CsInsn, riscv_const

from .base import InstructionSemantics


def _riscv_ids(*names):
    return {
        getattr(riscv_const, name)
        for name in names
        if hasattr(riscv_const, name)
    }


_STORE_IDS = _riscv_ids(
    "RISCV_INS_SB", "RISCV_INS_SH", "RISCV_INS_SW", "RISCV_INS_SD",
    "RISCV_INS_FSW", "RISCV_INS_FSD",
    "RISCV_INS_C_SW", "RISCV_INS_C_SD", "RISCV_INS_C_FSW", "RISCV_INS_C_FSD",
    "RISCV_INS_C_SWSP", "RISCV_INS_C_SDSP", "RISCV_INS_C_FSWSP", "RISCV_INS_C_FSDSP",
)
_BRANCH_IDS = _riscv_ids(
    "RISCV_INS_BEQ", "RISCV_INS_BNE", "RISCV_INS_BLT",
    "RISCV_INS_BGE", "RISCV_INS_BLTU", "RISCV_INS_BGEU",
    "RISCV_INS_C_BEQZ", "RISCV_INS_C_BNEZ",
)
_READ_WRITE_OPERAND0_MNEMONICS = {
    "c.add", "c.addi", "c.addi16sp", "c.addiw", "c.and", "c.andi",
    "c.or", "c.slli", "c.srai", "c.srli", "c.sub", "c.subw", "c.xor",
}
_REGISTER_BRANCH_MNEMONICS = {"jr", "c.jr", "jalr", "c.jalr"}
_NO_WRITE_MNEMONICS = {
    "ret", "jr", "c.jr", "j", "c.j", "tail", "ecall", "ebreak", "fence", "fence.i",
}
_CALL_LINK_MNEMONICS = {"call", "jal", "c.jal", "c.jalr"}


def riscv64_link_register(instruction: CsInsn) -> str:
    """Name of the register a jal/jalr writes its return address to.

    Capstone 6's real form, and Capstone 5's three-operand jalr, name the destination explicitly
    (``zero`` for a plain jump or return); Capstone 5's one-operand aliases imply ``ra``.
    """
    operands = instruction.operands
    if len(operands) >= 2 and operands[0].type == CS_OP_REG:
        return instruction.reg_name(operands[0].reg)
    return "ra"


def riscv64_is_call(instruction: CsInsn) -> bool:
    """A jal/jalr that links (Capstone 5 aliases, compressed forms and Capstone 6 real forms)."""
    mnemonic = instruction.mnemonic
    if mnemonic in ("call", "c.jal", "c.jalr"):
        return True
    return mnemonic in ("jal", "jalr") and riscv64_link_register(instruction) != "zero"


class RISCV64InstructionSemantics(InstructionSemantics):
    def instruction_regs_read_fallback(self, instruction: CsInsn):
        mnemonic = instruction.mnemonic
        operands = list(instruction.operands)

        if mnemonic == "ret":
            ra = self._register("ra")
            return {ra} if ra is not None else set()

        if self._is_store(instruction) or self._is_branch(instruction):
            return self._all_operand_registers(instruction)

        if mnemonic in _REGISTER_BRANCH_MNEMONICS:
            read_operands = operands[1:] if mnemonic == "jalr" and len(operands) > 1 else operands
            return self._operand_registers(instruction, read_operands)

        registers = set()
        if self._is_read_write_operand0(instruction) and operands:
            registers.update(self.analyzer._operand_registers(instruction, operands[0]))
        registers.update(self._operand_registers(instruction, operands[1:]))
        return registers

    def instruction_regs_write_fallback(self, instruction: CsInsn):
        mnemonic = instruction.mnemonic
        operands = list(instruction.operands)

        if mnemonic in _NO_WRITE_MNEMONICS or self._is_store(instruction) or self._is_branch(instruction):
            return set()
        if mnemonic in _CALL_LINK_MNEMONICS:
            ra = self._register("ra")
            return {ra} if ra is not None else set()
        if mnemonic == "jalr":
            if len(operands) > 1:
                return self.analyzer._operand_registers(instruction, operands[0], include_memory_base=False)
            ra = self._register("ra")
            return {ra} if ra is not None else set()
        return super().instruction_regs_write_fallback(instruction)

    def needs_explicit_read_fallback(self, instruction: CsInsn) -> bool:
        return True

    def ignore_register_name(self, reg_name: str) -> bool:
        return reg_name is not None and reg_name.lower() in ("zero", "x0")

    @staticmethod
    def _is_store(instruction: CsInsn) -> bool:
        return instruction.id in _STORE_IDS

    @staticmethod
    def _is_branch(instruction: CsInsn) -> bool:
        return instruction.id in _BRANCH_IDS

    @staticmethod
    def _is_read_write_operand0(instruction: CsInsn) -> bool:
        return instruction.mnemonic in _READ_WRITE_OPERAND0_MNEMONICS
