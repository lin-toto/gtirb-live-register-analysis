import unittest
import warnings
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import gtirb

from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.abis import _X86_64_ELF
from gtirb_live_register_analysis.manager import (
    LIVE_REGISTER_NAMES_AUXDATA,
    LIVE_REGISTER_NAMES_TYPE,
    LIVE_REGISTER_SETS_AUXDATA,
    LIVE_REGISTER_SETS_TYPE,
)
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder


class MetadataLifecycleTests(unittest.TestCase):
    def test_empty_instruction_anchors_decode_without_calling_capstone(self):
        for isa in (gtirb.Module.ISA.X64, gtirb.Module.ISA.ARM64,
                    gtirb.Module.ISA.ValidButUnsupported):
            with self.subTest(isa=isa):
                module = gtirb.Module(name="empty-anchor", isa=isa)
                if isa == gtirb.Module.ISA.ValidButUnsupported:
                    module.aux_data["archInfo"] = gtirb.AuxData(
                        {"ISA": "RISCV64"}, "mapping<string,string>")
                interval = gtirb.ByteInterval(address=0x1000, contents=bytearray(),
                                             section=gtirb.Section(module=module))
                anchor = gtirb.CodeBlock(size=0, byte_interval=interval)
                decoder = CachedGtirbInstructionDecoder(isa)
                decoder._get_riscv64_decoder = Mock(side_effect=AssertionError("empty decode"))
                self.assertEqual(list(decoder.get_instructions(anchor)), [])
                self.assertEqual(list(decoder.get_instructions(anchor)), [])

    def test_empty_rv32_block_still_rejects_unsupported_isa(self):
        module = gtirb.Module(name="unsupported-empty-anchor", isa=gtirb.Module.ISA.ValidButUnsupported)
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV32"}, "mapping<string,string>")
        block = gtirb.CodeBlock(size=0, byte_interval=gtirb.ByteInterval(
            contents=bytearray(), section=gtirb.Section(module=module)))
        with self.assertRaisesRegex(NotImplementedError, "RV32"):
            list(CachedGtirbInstructionDecoder(module.isa).get_instructions(block))

    def setUp(self):
        self.abi = _X86_64_ELF()
        self.module = gtirb.Module(
            name="metadata-test", isa=gtirb.Module.ISA.X64,
            byte_order=gtirb.Module.ByteOrder.Little,
            file_format=gtirb.Module.FileFormat.ELF)
        section = gtirb.Section(name=".text", module=self.module)
        self.interval = gtirb.ByteInterval(
            address=0x1000, contents=b"\x90\xc3", section=section)
        self.block = gtirb.CodeBlock(size=2, byte_interval=self.interval)
        self.function = SimpleNamespace(
            uuid=uuid4(), get_all_blocks=lambda: {self.block})
        registers = self.abi.all_registers()
        self.rax = self.abi.get_register("rax")
        self.rbx = self.abi.get_register("rbx")
        self.module.aux_data[LIVE_REGISTER_NAMES_AUXDATA] = gtirb.AuxData(
            [reg.name for reg in registers], LIVE_REGISTER_NAMES_TYPE)
        self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA] = gtirb.AuxData(
            {gtirb.Offset(self.block, 0): 1 << registers.index(self.rax),
             gtirb.Offset(self.block, 1): 0}, LIVE_REGISTER_SETS_TYPE)

    def test_refresh_reloads_table_and_decoder_without_python_analysis(self):
        manager = LiveRegisterManager(self.module, self.abi)
        manager.analyzer.analyze = Mock(side_effect=AssertionError("Python fallback"))
        manager.analyze(self.function)
        manager.add_live_registers(self.function, self.block, 0, {self.rbx})
        old_masks = self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data

        self.interval.contents = b"\x90" + self.interval.contents
        self.block.size += 1
        self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data = {
            gtirb.Offset(self.block, offset.displacement + 1): mask
            for offset, mask in old_masks.items()
        }
        manager.refresh(preserve_liveness=True)
        manager.analyze(self.function)
        self.assertEqual(manager.analysis_source, "ddisasm")
        self.assertEqual(manager.live_registers(self.function, self.block, 0),
                         set(self.abi.all_registers()))
        self.assertEqual(manager.live_registers(self.function, self.block, 1), {self.rax})
        self.assertEqual(manager.live_registers(self.function, self.block, 2), set())
        self.assertEqual(old_masks[gtirb.Offset(self.block, 0)],
                         1 << self.abi.all_registers().index(self.rax))

    def test_empty_valid_metadata_does_not_fall_back(self):
        self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data.clear()
        manager = LiveRegisterManager(self.module, self.abi)
        manager.analyzer.analyze = Mock(side_effect=AssertionError("Python fallback"))
        manager.analyze(self.function)
        self.assertEqual(manager.analysis_source, "ddisasm")
        self.assertEqual(manager.free_registers(self.function, self.block, 0), set())
        self.assertEqual(manager.free_registers(self.function, self.block, -1), set())

    def test_unspecified_edit_invalidates_predecessors_and_callers_too(self):
        ir = gtirb.IR(modules=[self.module])
        caller_interval = gtirb.ByteInterval(
            address=0x2000, contents=b"\x90\xc3", section=self.block.section)
        caller = gtirb.CodeBlock(size=2, byte_interval=caller_interval)
        ir.cfg.add(gtirb.Edge(caller, self.block, gtirb.Edge.Label(gtirb.Edge.Type.Call)))
        sets = self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data
        sets[gtirb.Offset(caller, 0)] = 0
        sets[gtirb.Offset(caller, 1)] = 0
        manager = LiveRegisterManager(self.module, self.abi)
        manager.analyzer.analyze = Mock(side_effect=AssertionError("Python fallback"))
        manager.analyze(self.function)

        # A new use in a callee invalidates more than its own instruction mask.
        self.interval.contents = bytes.fromhex("4889d8c3")
        self.block.size = 4
        with self.assertWarnsRegex(RuntimeWarning, "invalidating 4.*unspecified edit"):
            manager.refresh()
        self.assertEqual(self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data, {})
        self.assertIn(LIVE_REGISTER_NAMES_AUXDATA, self.module.aux_data)
        self.assertEqual(manager.analysis_source, "ddisasm")
        manager.analyze(self.function)
        self.assertEqual(manager.free_registers(self.function, self.block, 0), set())
        caller_function = SimpleNamespace(uuid=uuid4(), get_all_blocks=lambda: {caller})
        manager.analyze(caller_function)
        self.assertEqual(manager.free_registers(caller_function, caller, 0), set())

    def test_missing_metadata_warns_with_scope_and_uses_block_fallback(self):
        self.module.aux_data.clear()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            manager = LiveRegisterManager(self.module, self.abi, analysis_scope="block")
            manager.refresh(preserve_liveness=True)
        self.assertEqual(len(caught), 1)
        self.assertRegex(str(caught[0].message),
                         "metadata-test.*Python block-scope.*both live-register")
        manager.analyze(self.function)
        self.assertEqual(manager.analysis_source, "python")
        for index in range(2):
            self.assertEqual(manager.live_registers(self.function, self.block, index),
                             set(self.abi.all_registers()))

    def test_block_fallback_does_not_wrap_to_last_instruction(self):
        self.module.aux_data.clear()
        # RAX is dead before its full definition, but live at the following NOP.
        self.interval.contents = bytes.fromhex("b80100000090")
        self.block.size = 6
        with self.assertWarns(RuntimeWarning):
            manager = LiveRegisterManager(self.module, self.abi, analysis_scope="block")
        manager.analyze(self.function)
        self.assertNotIn(self.rax, manager.live_registers(self.function, self.block, 0))
        self.assertIn(self.rax, manager.live_registers(self.function, self.block, 1))

    def test_invalid_mask_is_all_live_without_discarding_valid_metadata(self):
        self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data[gtirb.Offset(self.block, 0)] = -1
        with self.assertWarnsRegex(RuntimeWarning, "metadata-test.*discarded 1.*retaining DDisasm"):
            manager = LiveRegisterManager(self.module, self.abi)
        manager.analyzer.analyze = Mock(side_effect=AssertionError("Python fallback"))
        manager.analyze(self.function)
        self.assertEqual(manager.analysis_source, "ddisasm")
        self.assertEqual(manager.live_registers(self.function, self.block, 0),
                         set(self.abi.all_registers()))
        self.assertEqual(manager.live_registers(self.function, self.block, 1), set())
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            manager.refresh(preserve_liveness=True)
        self.assertEqual(caught, [])

    def test_stale_entries_are_removed_before_rewriter_offset_hooks(self):
        sets = self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data
        valid = dict(sets)
        sets.update({
            "not-an-offset": 0,
            gtirb.Offset(gtirb.CodeBlock(size=1), 0): 0,
            gtirb.Offset(self.block, self.block.size): 0,
            gtirb.Offset(self.block, "not-an-integer"): 0,
            gtirb.Offset(self.interval, 0): 0,
        })
        with self.assertWarnsRegex(RuntimeWarning, "discarded 5"):
            manager = LiveRegisterManager(self.module, self.abi)
        self.assertEqual(manager.analysis_source, "ddisasm")
        self.assertEqual(self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data, valid)

    def test_incompatible_register_names_still_require_fallback(self):
        self.module.aux_data[LIVE_REGISTER_NAMES_AUXDATA].data = ["rax"]
        with self.assertWarnsRegex(RuntimeWarning, "omits allocatable"):
            manager = LiveRegisterManager(self.module, self.abi)
        self.assertEqual(manager.analysis_source, "python")

    def test_non_mapping_metadata_warns_instead_of_crashing(self):
        self.module.aux_data[LIVE_REGISTER_SETS_AUXDATA].data = []
        with self.assertWarnsRegex(RuntimeWarning, "metadata-test.*not a mapping"):
            manager = LiveRegisterManager(self.module, self.abi)
        self.assertEqual(manager.analysis_source, "python")


if __name__ == "__main__":
    unittest.main()
