import unittest

import gtirb
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from gtirb_live_register_analysis.analysis import LiveRegisterAnalyzer
from gtirb_live_register_analysis.abis import _X86_64_ELF


class _SequenceDecoder:
    def __init__(self, instructions):
        self.instructions = instructions

    def get_instructions(self, _block):
        return self.instructions


class _SingleBlockFunction:
    def __init__(self, block):
        self.block = block

    def get_all_blocks(self):
        return {self.block}

    def get_entry_blocks(self):
        return {self.block}

    def get_exit_blocks(self):
        return {self.block}


class X64AdoxLivenessTests(unittest.TestCase):
    @staticmethod
    def _decode(encoded: str):
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        return next(decoder.disasm(bytes.fromhex(encoded), 0x1000))

    def setUp(self):
        self.abi = _X86_64_ELF()
        self.analyzer = LiveRegisterAnalyzer(self.abi, decoder=None)

    def test_adox_destination_is_read_and_written(self):
        # adox r12, r13
        instruction = self._decode("f3 4d 0f 38 f6 e5")

        self.assertIn(
            self.abi.get_register("r12"),
            self.analyzer._instruction_regs_read(instruction),
        )
        self.assertIn(
            self.abi.get_register("r12"),
            self.analyzer._instruction_regs_write(instruction),
        )

    def test_adox_input_stays_live_across_an_intervening_load(self):
        instructions = [
            # mulx r12, rax, qword ptr [rcx + 0x10]
            self._decode("c4 62 fb f6 61 10"),
            # mov rdi, qword ptr [rsp + 0x30]
            self._decode("48 8b 7c 24 30"),
            # adox r12, r13
            self._decode("f3 4d 0f 38 f6 e5"),
            # Terminate r12's live range so the assertion below specifically
            # depends on ADOX reading its destination.
            self._decode("49 c7 c4 00 00 00 00"),  # mov r12, 0
        ]
        block = gtirb.CodeBlock(size=sum(instruction.size for instruction in instructions))
        analyzer = LiveRegisterAnalyzer(
            self.abi,
            _SequenceDecoder(instructions),
        )
        live = analyzer.analyze(_SingleBlockFunction(block))

        self.assertIn(self.abi.get_register("r12"), live[block.uuid][1])


if __name__ == "__main__":
    unittest.main()
