import unittest

from gtirb_live_register_analysis.analysis import LiveRegisterAnalyzer
from gtirb_live_register_analysis.abis import (
    _ARM64_ELF,
    _RISCV64_ELF,
    _X86_64_ELF,
)


class _FakeABI:
    analysis_arch = None
    _register_map = {}

    @staticmethod
    def is_call_instruction(instruction):
        return instruction.mnemonic == "call"

    @staticmethod
    def conservative_call_registers():
        return {"abi-argument", "private-call-input", "scratch"}


class _FakeInstruction:
    operands = ()

    def __init__(self, mnemonic):
        self.mnemonic = mnemonic

    @staticmethod
    def regs_access():
        return (), ()

    @staticmethod
    def reg_name(_):
        return ""


class ConservativeCallLivenessTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = LiveRegisterAnalyzer(_FakeABI(), decoder=None)

    def test_call_reads_all_conservative_call_registers(self):
        registers = self.analyzer._instruction_regs_read(
            _FakeInstruction("call")
        )

        self.assertEqual(
            registers,
            {"abi-argument", "private-call-input", "scratch"},
        )

    def test_non_call_does_not_read_call_registers(self):
        registers = self.analyzer._instruction_regs_read(
            _FakeInstruction("nop")
        )

        self.assertEqual(registers, set())

    def test_every_supported_abi_preserves_all_scratch_registers_at_calls(self):
        for abi_type in (_X86_64_ELF, _ARM64_ELF, _RISCV64_ELF):
            with self.subTest(abi=abi_type.__name__):
                abi = abi_type()
                self.assertTrue(
                    set(abi._scratch_registers()).issubset(
                        abi.conservative_call_registers()
                    )
                )


if __name__ == "__main__":
    unittest.main()
