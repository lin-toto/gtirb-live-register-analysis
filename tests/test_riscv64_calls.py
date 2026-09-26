import unittest

import capstone

from gtirb_live_register_analysis.abis import _RISCV64_ELF
from gtirb_live_register_analysis.utils import RISCV64_MODE, configure_riscv64


class RISCV64CallTests(unittest.TestCase):
    """Only a jal/jalr that writes a link register is a call, however Capstone presents it."""

    CASES = (
        ("ef000010", True),   # jal ra, 256
        ("6f000010", False),  # jal zero, 256 (j)
        ("e7800700", True),   # jalr ra, 0(a5)
        ("e7808700", True),   # jalr ra, 8(a5)
        ("67800700", False),  # jalr zero, 0(a5) (jr a5)
        ("67800000", False),  # jalr zero, 0(ra) (ret)
        ("8297", True),       # c.jalr a5
        ("8287", False),      # c.jr a5
        ("8280", False),      # c.jr ra (ret)
        ("01a0", False),      # c.j 0
    )

    def test_calls_write_a_link_register(self):
        abi = _RISCV64_ELF()
        decoder = configure_riscv64(capstone.Cs(capstone.CS_ARCH_RISCV, RISCV64_MODE))
        for encoded, is_call in self.CASES:
            instruction = next(decoder.disasm(bytes.fromhex(encoded), 0x1000))
            with self.subTest(instruction=f"{instruction.mnemonic} {instruction.op_str}"):
                self.assertEqual(abi.is_call_instruction(instruction), is_call)


if __name__ == "__main__":
    unittest.main()
