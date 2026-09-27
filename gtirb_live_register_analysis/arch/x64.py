from capstone import CsInsn, CsError, CS_GRP_INT
from capstone import x86_const as x86

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


_FLAGS = ("CF", "PF", "AF", "ZF", "SF", "OF")
_FLAG_READS = tuple(sum(getattr(x86, f"X86_EFLAGS_{op}_{flag}")
                        for op in ("TEST", "PRIOR")) for flag in _FLAGS)
_FLAG_WRITES = tuple(sum(getattr(x86, f"X86_EFLAGS_{op}_{flag}")
                         for op in ("MODIFY", "RESET", "SET", "UNDEFINED")) for flag in _FLAGS)
_UNTRACKED_FLAG_READS = sum(getattr(x86, f"X86_EFLAGS_{op}_{flag}", 0)
                            for op in ("TEST", "PRIOR")
                            for flag in ("TF", "IF", "DF", "NT", "RF", "AC"))
_SHIFTS = {"shl", "sal", "shr", "sar", "shld", "shrd", "rol", "ror", "rcl", "rcr"}
_FCMOV_FLAG_READS = {
    "fcmovb": 1, "fcmovnb": 1,       # CF
    "fcmove": 8, "fcmovne": 8,       # ZF
    "fcmovbe": 9, "fcmovnbe": 9,     # CF | ZF
    "fcmovu": 2, "fcmovnu": 2,       # PF
}


class X64InstructionSemantics(InstructionSemantics):
    flag_mask = 63

    def flag_effects(self, instruction: CsInsn):
        # eflags and fpu_flags share a union. FCOMI has a real flags-register
        # access; other x87 status operations must not be interpreted as EFLAGS.
        if instruction.group(CS_GRP_INT):
            return 63, 0, 63
        mnemonic = _base_mnemonic(instruction)
        # Capstone 6 Alpha11 omits FCMOV's integer-flag access entirely. Its
        # fpu_flags/eflags union must not be read as integer flag definitions.
        if mnemonic in _FCMOV_FLAG_READS:
            return _FCMOV_FLAG_READS[mnemonic], 0, 63
        try:
            reads, writes = instruction.regs_access()
        except CsError:
            return 63, 0, 63
        # These consume carry even when Capstone omits its read metadata.
        explicit_read = 1 if mnemonic in ("rcl", "rcr", "cmc") else 0
        if not any(instruction.reg_name(r) in ("rflags", "eflags") for r in (*reads, *writes)):
            return explicit_read, 0, 63
        bits = instruction.eflags
        read = explicit_read | sum(1 << i for i, mask in enumerate(_FLAG_READS) if bits & mask)
        kill = sum(1 << i for i, mask in enumerate(_FLAG_WRITES) if bits & mask)
        # Capstone 6 Alpha11 marks LAHF's RFLAGS read but leaves eflags=0.
        # ADOX similarly lists an aggregate read but only an OF write in
        # eflags. Unresolved reads preserve all bits, even with write metadata.
        # A resolved read of DF (or another untracked flag) alone is not missing.
        if mnemonic == 'lahf':
            read = 31
        elif (not read and not bits & _UNTRACKED_FLAG_READS
              and any(instruction.reg_name(r) in ('rflags', 'eflags') for r in reads)):
            read = 63
        if mnemonic in _SHIFTS:
            count = instruction.operands[-1]
            width = instruction.operands[0].size * 8
            if count.type != x86.X86_OP_IMM:
                kill = 0
            else:
                effective = count.imm & (63 if width == 64 else 31)
                if mnemonic in ("rol", "ror"):
                    effective %= width
                elif mnemonic in ("rcl", "rcr") and width < 32:
                    effective %= width + 1
                if effective == 0:
                    kill = 0
        return read, kill, 63

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
            # TEST never writes a GPR. Independent flags are handled separately.
            return set()
        return None

    def _registers(self, names):
        return {reg for reg in (self._register(name) for name in names) if reg is not None}

    def register_write_kills(self, instruction: CsInsn, reg, reg_name: str) -> bool:
        if reg == self.abi.flag_register():
            # Legacy aggregate mode is retained by --conservative-flags. The
            # independent flag pass below replaces this bit in normal mode.
            return instruction.id in {x86.X86_INS_ADC, x86.X86_INS_ADD, x86.X86_INS_CMP,
                                      x86.X86_INS_NEG, x86.X86_INS_SBB, x86.X86_INS_SUB}
        return self.analyzer._register_access_size(reg, reg_name) > 16
