from .base import InstructionSemantics


class AArch64InstructionSemantics(InstructionSemantics):
    def ignore_register_name(self, reg_name: str) -> bool:
        return reg_name is not None and reg_name.lower() in ("xzr", "wzr")
