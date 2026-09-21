import unittest
import uuid

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function

from gtirb_live_register_analysis.analysis import LiveRegisterAnalyzer
from gtirb_live_register_analysis.abis import _X86_64_ELF


class X64FlagsLivenessTests(unittest.TestCase):
    def setUp(self):
        self.abi = _X86_64_ELF()
        self.decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)

    def test_partial_writers_preserve_the_flags_needed_later(self):
        cases = (
            # mov rax,rbx; inc/dec rbx; adc rax,rdx; ret
            "48 89 d8 48 ff c3 48 11 d0 c3",
            "48 89 d8 48 ff cb 48 11 d0 c3",
            # mov rax,rbx; clc/stc; seto al; ret
            "48 89 d8 f8 0f 90 c0 c3",
            "48 89 d8 f9 0f 90 c0 c3",
            # mov rax,rbx; shl rbx,cl / shl rbx,0; adc rax,rdx; ret
            "48 89 d8 48 d3 e3 48 11 d0 c3",
            "48 89 d8 48 c1 e3 00 48 11 d0 c3",
            # The effective shift count is also zero after masking 64.
            "48 89 d8 48 c1 e3 40 48 11 d0 c3",
        )
        for encoded in cases:
            with self.subTest(encoded=encoded):
                code = bytes.fromhex(encoded)
                interval = gtirb.ByteInterval(address=0x1000, contents=code)
                block = gtirb.CodeBlock(size=len(code), byte_interval=interval)
                function = Function(uuid.uuid4(), {block}, {block}, exitBlocks={block})
                analyzer = LiveRegisterAnalyzer(self.abi, self.decoder)
                live = analyzer.analyze(function)[block.uuid]
                for index in (0, 1, 2):
                    self.assertIn(self.abi.flag_register(), live[index])

    def test_complete_arithmetic_writes_end_the_old_flags_live_range(self):
        for encoded in ("48 01 d8", "48 29 d8", "48 39 d8", "48 f7 d8",
                        "00 d8", "66 01 d8", "f0 48 01 18"):
            with self.subTest(encoded=encoded):
                # mov rax,rbx; full arithmetic definition; seto dl; ret
                code = bytes.fromhex(f"48 89 d8 {encoded} 0f 90 c2 c3")
                interval = gtirb.ByteInterval(address=0x1000, contents=code)
                block = gtirb.CodeBlock(size=len(code), byte_interval=interval)
                function = Function(uuid.uuid4(), {block}, {block}, exitBlocks={block})
                analyzer = LiveRegisterAnalyzer(self.abi, self.decoder)
                live = analyzer.analyze(function)[block.uuid]
                self.assertNotIn(self.abi.flag_register(), live[0])
                self.assertNotIn(self.abi.flag_register(), live[1])
                self.assertIn(self.abi.flag_register(), live[2])

    def test_carry_inputs_remain_live_despite_complete_outputs(self):
        for encoded in ("48 11 d8", "48 19 d8"):  # adc/sbb rax,rbx
            with self.subTest(encoded=encoded):
                code = bytes.fromhex(f"48 89 d8 {encoded} 0f 90 c2 c3")
                interval = gtirb.ByteInterval(address=0x1000, contents=code)
                block = gtirb.CodeBlock(size=len(code), byte_interval=interval)
                function = Function(uuid.uuid4(), {block}, {block}, exitBlocks={block})
                analyzer = LiveRegisterAnalyzer(self.abi, self.decoder)
                instruction = list(self.decoder.get_instructions(block))[1]
                self.assertIn(self.abi.flag_register(), analyzer._instruction_regs_write(instruction))
                live = analyzer.analyze(function)[block.uuid]
                for index in (0, 1, 2):
                    self.assertIn(self.abi.flag_register(), live[index])

    def test_other_flag_writes_remain_conservative(self):
        for encoded in (
                "48 ff c0", "48 ff c8",  # inc/dec rax
                "f8", "f9", "f5", "9e",  # clc/stc/cmc/sahf
                "fc", "fd",  # cld/std change DF, not arithmetic flags
                "48 d3 e0", "48 c1 e0 00", "48 c1 e0 40",  # shl
                "48 d1 c0",  # rol rax,1
                "66 48 0f 38 f6 c3", "f3 48 0f 38 f6 c3",  # adcx/adox
                "48 21 d8", "48 09 d8", "48 31 d8", "48 85 d8"):  # AF undefined
            with self.subTest(encoded=encoded):
                code = bytes.fromhex(encoded)
                interval = gtirb.ByteInterval(address=0x1000, contents=code)
                block = gtirb.CodeBlock(size=len(code), byte_interval=interval)
                instruction = next(iter(self.decoder.get_instructions(block)))
                analyzer = LiveRegisterAnalyzer(self.abi, self.decoder)
                self.assertNotIn(self.abi.flag_register(), analyzer._instruction_regs_write(instruction))

    def test_gpr_kills_still_distinguish_partial_and_zero_extending_writes(self):
        analyzer = LiveRegisterAnalyzer(self.abi, self.decoder)
        for encoded, kills in (("b0 00", False), ("66 b8 00 00", False),
                               ("b8 00 00 00 00", True),
                               ("48 c7 c0 00 00 00 00", True)):
            with self.subTest(encoded=encoded):
                code = bytes.fromhex(encoded)
                interval = gtirb.ByteInterval(address=0x1000, contents=code)
                block = gtirb.CodeBlock(size=len(code), byte_interval=interval)
                instruction = next(iter(self.decoder.get_instructions(block)))
                self.assertEqual(self.abi.get_register("rax") in
                                 analyzer._instruction_regs_write(instruction), kills)


if __name__ == "__main__":
    unittest.main()
