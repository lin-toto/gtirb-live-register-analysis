from typing import Optional, Set

from gtirb_rewriting.abi import ABI
from gtirb_rewriting.assembly import Register


class AnalysisAwareABI(ABI):
    analysis_arch = None

    def calling_convention_registers(self) -> Set[Register]:
        return {
            self.get_register(name)
            for name in self.calling_convention().registers
        }

    def callee_saved_registers(self) -> Set[Register]:
        return set(self.all_registers()).difference(self.caller_saved_registers())

    def return_registers(self) -> Set[Register]:
        raise NotImplementedError

    def flag_register(self) -> Optional[Register]:
        raise NotImplementedError

    def is_call_instruction(self, instruction) -> bool:
        return instruction.mnemonic == "call"
