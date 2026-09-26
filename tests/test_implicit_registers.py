import unittest

import capstone

from gtirb_live_register_analysis.analysis import LiveRegisterAnalyzer
from gtirb_live_register_analysis.abis import _ARM64_ELF, _RISCV64_ELF, _X86_64_ELF


class ImplicitRegistersTests(unittest.TestCase):
    def test_system_call_boundaries_preserve_all_tracked_registers(self):
        cases = (
            (_X86_64_ELF, capstone.CS_ARCH_X86, capstone.CS_MODE_64, "0f05"),
            (_ARM64_ELF, getattr(capstone, "CS_ARCH_AARCH64", getattr(capstone, "CS_ARCH_ARM64", None)), capstone.CS_MODE_ARM, "010000d4"),
            (_RISCV64_ELF, capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64, "73000000"),
        )
        for abi_class, architecture, mode, encoded in cases:
            with self.subTest(abi=abi_class.__name__):
                abi = abi_class()
                decoder = capstone.Cs(architecture, mode)
                decoder.detail = True
                instruction = next(decoder.disasm(bytes.fromhex(encoded), 0x1000))
                analyzer = LiveRegisterAnalyzer(abi, None)
                self.assertEqual(analyzer._instruction_regs_read(instruction),
                                 set(abi.all_registers()))

    def test_adx_destinations_are_inputs(self):
        abi = _X86_64_ELF()
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        analyzer = LiveRegisterAnalyzer(abi, None)
        for encoded in ("f3480f38f6c2", "66480f38f6c2"):
            instruction = next(decoder.disasm(bytes.fromhex(encoded), 0x1000))
            with self.subTest(instruction=instruction.mnemonic):
                reads = analyzer._instruction_regs_read(instruction)
                self.assertTrue({abi.get_register("rax"), abi.get_register("rdx"),
                                 abi.flag_register()}.issubset(reads))


if __name__ == "__main__":
    unittest.main()
