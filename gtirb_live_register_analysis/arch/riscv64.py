from capstone import CsInsn

from .base import InstructionSemantics


def riscv64_link_register(instruction: CsInsn) -> str:
    """Name of the register a jal/jalr writes its return address to.

    The real instruction form names it as the first operand (``zero`` for a plain jump or return).
    """
    return instruction.reg_name(instruction.operands[0].reg)


def riscv64_is_call(instruction: CsInsn) -> bool:
    """A jal/jalr that links, including the compressed forms."""
    return instruction.mnemonic in ("jal", "jalr") and riscv64_link_register(instruction) != "zero"


class RISCV64InstructionSemantics(InstructionSemantics):
    # Register accesses come from Capstone's real, uncompressed details (utils.configure_riscv64),
    # which list every operand, including the tied destination of compressed instructions.

    def ignore_register_name(self, reg_name: str) -> bool:
        return reg_name is not None and reg_name.lower() in ("zero", "x0")
