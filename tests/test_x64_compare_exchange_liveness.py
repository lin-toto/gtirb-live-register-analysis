import unittest

import capstone

from gtirb_live_register_analysis.abis import _X86_64_ELF
from gtirb_live_register_analysis.analysis import LiveRegisterAnalyzer


class X64CompareExchangeTests(unittest.TestCase):
    """CMPXCHG8B/16B read edx:eax and ecx:ebx and write edx:eax (Capstone 6 reports only al)."""

    def test_register_pairs(self):
        abi = _X86_64_ELF()
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        analyzer = LiveRegisterAnalyzer(abi, None)
        names = lambda regs: {reg.name for reg in regs}
        for encoded in ("0fc70f", "f00fc70f", "480fc70f", "f0480fc70f"):  # [lock] cmpxchg8b/16b [rdi]
            instruction = next(decoder.disasm(bytes.fromhex(encoded), 0x1000))
            with self.subTest(instruction=instruction.mnemonic):
                self.assertTrue({"rax", "rbx", "rcx", "rdx", "rdi"} <= names(analyzer._instruction_regs_read(instruction)))
                self.assertEqual(names(analyzer._instruction_regs_write(instruction)), {"rax", "rdx"})


if __name__ == "__main__":
    unittest.main()
