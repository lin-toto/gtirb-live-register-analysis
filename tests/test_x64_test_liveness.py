import unittest
import uuid

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis.analysis import LiveRegisterAnalyzer
from gtirb_live_register_analysis.abis import _X86_64_ELF


class X64TestLivenessTests(unittest.TestCase):
    def test_memory_test_keeps_input_live_across_prior_store(self):
        abi = _X86_64_ELF()
        decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
        for encoded in ('408437', '668537', '8537', '488537'):
            # mov [rdi],ecx; test [rdi],rsi-part; sete al; mov esi,0; ret
            code = bytes.fromhex('890f' + encoded + '0f94c0be00000000c3')
            interval = gtirb.ByteInterval(address=0x1000, contents=code)
            block = gtirb.CodeBlock(size=len(code), byte_interval=interval)
            function = Function(uuid.uuid4(), {block}, {block}, exitBlocks={block})
            analyzer = LiveRegisterAnalyzer(abi, decoder)
            live = analyzer.analyze(function)[block.uuid]
            instructions = list(decoder.get_instructions(block))
            with self.subTest(encoding=encoded):
                self.assertIn(abi.get_register('rsi'), live[0])
                self.assertIn(abi.get_register('rsi'), live[1])
                self.assertNotIn(abi.get_register('rsi'), live[2])
                self.assertNotIn(abi.get_register('rsi'), analyzer._instruction_regs_write(instructions[1]))


if __name__ == '__main__':
    unittest.main()
