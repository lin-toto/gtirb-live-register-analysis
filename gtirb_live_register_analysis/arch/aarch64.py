from capstone import CsError, CS_GRP_INT

from .base import InstructionSemantics


class AArch64InstructionSemantics(InstructionSemantics):
    flag_mask = 1

    def flag_effects(self, instruction):
        if instruction.group(CS_GRP_INT):
            return 1, 0, 1
        try:
            reads, writes = instruction.regs_access()
        except CsError:
            return 1, 0, 1
        read = any(instruction.reg_name(r) == "nzcv" for r in reads)
        write = any(instruction.reg_name(r) == "nzcv" for r in writes)
        return int(read), int(write), 1

    def ignore_register_name(self, reg_name: str) -> bool:
        return reg_name is not None and reg_name.lower() in ("xzr", "wzr")
