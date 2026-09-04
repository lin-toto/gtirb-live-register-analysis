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

    def conservative_call_registers(self) -> Set[Register]:
        """Registers that an unmodeled callee may consume as inputs.

        ABI argument registers alone are insufficient for local assembly
        helpers, which may use a private register calling convention.  Keep
        every register that patch allocation could otherwise use as scratch
        live at calls, while retaining non-GPR ABI arguments such as XMM
        registers.
        """
        return set(self._scratch_registers()).union(
            self.calling_convention_registers()
        )

    def callee_saved_registers(self) -> Set[Register]:
        return set(self.all_registers()).difference(self.caller_saved_registers())

    def return_registers(self) -> Set[Register]:
        raise NotImplementedError

    def flag_register(self) -> Optional[Register]:
        raise NotImplementedError

    def is_call_instruction(self, instruction) -> bool:
        return instruction.mnemonic == "call"
