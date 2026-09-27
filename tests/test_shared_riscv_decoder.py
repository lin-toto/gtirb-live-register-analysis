import sys
import unittest
from unittest.mock import patch

import gtirb

from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder


class SharedRiscvDecoderTests(unittest.TestCase):
    def test_missing_fork_api_only_rejects_riscv(self):
        module = gtirb.Module(
            name="probe", isa=gtirb.Module.ISA.X64,
            byte_order=gtirb.Module.ByteOrder.Little,
        )
        section = gtirb.Section(name=".text", module=module)
        interval = gtirb.ByteInterval(contents=b"\x90", section=section)
        block = gtirb.CodeBlock(size=1, byte_interval=interval)
        decoder = CachedGtirbInstructionDecoder(module.isa)
        with patch.dict(sys.modules, {"gtirb_rewriting.decoder": None}):
            self.assertEqual(next(decoder.get_instructions(block)).mnemonic, "nop")
            with self.assertRaisesRegex(RuntimeError, "RV64 decoding requires.*fork"):
                decoder._get_riscv64_decoder(block)
