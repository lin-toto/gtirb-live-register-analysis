from capstone import CsInsn
from capstone.x86_const import (
    X86_INS_ADC, X86_INS_ADD, X86_INS_CMP, X86_INS_NEG, X86_INS_SBB, X86_INS_SUB,
)

from .base import InstructionSemantics


_EXPLICIT_READ_MNEMONICS = {"adox", "test"}
# CMPXCHG8B/16B compare edx:eax (rdx:rax) with memory, store ecx:ebx (rcx:rbx) if equal and load the
# memory into edx:eax otherwise. Capstone 6.0.0-Alpha11 reports only al for both register sets.
_COMPARE_EXCHANGE_PAIRS = {
    "cmpxchg8b": (("eax", "ebx", "ecx", "edx"), ("eax", "edx")),
    "cmpxchg16b": (("rax", "rbx", "rcx", "rdx"), ("rax", "rdx")),
}


def _base_mnemonic(instruction: CsInsn) -> str:
    # Prefixes are part of Capstone's mnemonic ("lock cmpxchg8b").
    return instruction.mnemonic.split()[-1]


_FULL_ARITHMETIC_FLAGS_WRITERS = {
    X86_INS_ADC, X86_INS_ADD, X86_INS_CMP, X86_INS_NEG, X86_INS_SBB, X86_INS_SUB,
}


class X64InstructionSemantics(InstructionSemantics):
    def instruction_regs_read_fallback(self, instruction: CsInsn):
        pair = _COMPARE_EXCHANGE_PAIRS.get(_base_mnemonic(instruction))
        if pair is not None:
            return self._all_operand_registers(instruction) | self._registers(pair[0])
        if instruction.mnemonic in _EXPLICIT_READ_MNEMONICS:
            return self._all_operand_registers(instruction)
        return super().instruction_regs_read_fallback(instruction)

    def needs_explicit_read_fallback(self, instruction: CsInsn) -> bool:
        # Capstone (5 and 6.0) marks ADOX's destination as write-only even
        # though its previous value is an input to the addition, and can omit
        # TEST's register operand in memory-first forms.
        return (instruction.mnemonic in _EXPLICIT_READ_MNEMONICS or
                _base_mnemonic(instruction) in _COMPARE_EXCHANGE_PAIRS)

    def instruction_regs_write_override(self, instruction: CsInsn):
        pair = _COMPARE_EXCHANGE_PAIRS.get(_base_mnemonic(instruction))
        if pair is not None:
            # edx:eax is loaded only when the comparison fails, but it is also read, so counting it as
            # written cannot end a live value early; ZF alone does not kill the tracked flags.
            return self._registers(pair[1])
        if instruction.mnemonic.startswith("cmov") or instruction.mnemonic == "test":
            # TEST never writes a GPR; its flag write is not a complete kill
            # of the tracked arithmetic flags (AF is undefined).
            return set()
        return None

    def _registers(self, names):
        return {reg for reg in (self._register(name) for name in names) if reg is not None}

    def register_write_kills(self, instruction: CsInsn, reg, reg_name: str) -> bool:
        if reg == self.abi.flag_register():
            # The tracked value is CF/PF/AF/ZF/SF/OF, not DF or full RFLAGS.
            # These instructions define all six unconditionally; ADC/SBB's
            # incoming carry remains a read in the liveness transfer. Keep
            # partial/conditional writes and undefined outputs conservative.
            # Instruction IDs also cover prefixed forms such as LOCK ADD.
            return instruction.id in _FULL_ARITHMETIC_FLAGS_WRITERS
        return self.analyzer._register_access_size(reg, reg_name) > 16
