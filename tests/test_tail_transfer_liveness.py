import unittest
import warnings
from uuid import uuid4

import gtirb
from gtirb_functions import Function

from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.abis import _RISCV64_ELF

ARGUMENTS = {f"a{i}" for i in range(8)}


def riscv_function(*block_bytes):
    """One RV64 function made of the given blocks, laid out back to back from 0x1000."""
    ir = gtirb.IR()
    module = gtirb.Module(name="tail", isa=gtirb.Module.ISA.ValidButUnsupported,
                          file_format=gtirb.Module.FileFormat.ELF,
                          byte_order=gtirb.Module.ByteOrder.Little, ir=ir)
    module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
    section = gtirb.Section(name=".text", module=module,
                            flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Loaded,
                                   gtirb.Section.Flag.Readable, gtirb.Section.Flag.Initialized})
    contents = b"".join(bytes.fromhex(part) for part in block_bytes)
    interval = gtirb.ByteInterval(address=0x1000, contents=contents, section=section)
    blocks, offset = [], 0
    for part in block_bytes:
        size = len(bytes.fromhex(part))
        blocks.append(gtirb.CodeBlock(offset=offset, size=size, byte_interval=interval))
        offset += size
    symbol = gtirb.Symbol(name="caller", payload=blocks[0], module=module)
    function_id = uuid4()
    module.aux_data["functionEntries"] = gtirb.AuxData({function_id: {blocks[0]}}, "mapping<UUID,set<UUID>>")
    module.aux_data["functionBlocks"] = gtirb.AuxData({function_id: set(blocks)}, "mapping<UUID,set<UUID>>")
    module.aux_data["functionNames"] = gtirb.AuxData({function_id: symbol}, "mapping<UUID,UUID>")
    external = gtirb.ProxyBlock(module=module)
    gtirb.Symbol(name="external_function", payload=external, module=module)
    return ir, module, blocks, external


def free_arguments(module, scope="function", block=None):
    function = next(iter(Function.build_functions(module)))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        manager = LiveRegisterManager(module, _RISCV64_ELF(), analysis_scope=scope)
    manager.analyze(function)
    block = block or next(iter(function.get_entry_blocks()))
    return {reg.name for reg in manager.free_registers(function, block, 0)} & ARGUMENTS


class TailTransferLivenessTests(unittest.TestCase):
    """A jump out of the function hands its registers to the callee; a return does not."""

    def test_tail_transfers_keep_every_argument_live(self):
        for encoded, direct in (("67008300", False),   # jalr zero, 8(t1)
                                ("67000300", False),   # jalr zero, 0(t1)
                                ("6f000010", True)):   # jal zero, <external>
            with self.subTest(instruction=encoded):
                ir, module, (block,), external = riscv_function(encoded)
                ir.cfg.add(gtirb.Edge(block, external, gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=direct)))
                self.assertEqual(free_arguments(module), set())

    def test_a_conditional_tail_branch_keeps_both_paths(self):
        # beq a0, zero, <external>; then a return that uses only a0 and a1.
        ir, module, (branch, ret), external = riscv_function("63000500", "67800000")
        ir.cfg.add(gtirb.Edge(branch, external, gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=True)))
        ir.cfg.add(gtirb.Edge(branch, ret, gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
        ir.cfg.add(gtirb.Edge(ret, external, gtirb.Edge.Label(gtirb.Edge.Type.Return)))
        self.assertEqual(free_arguments(module), set())

    def test_returns_and_internal_jumps_stay_precise(self):
        ir, module, (ret,), external = riscv_function("67800000")   # jalr zero, 0(ra)
        ir.cfg.add(gtirb.Edge(ret, external, gtirb.Edge.Label(gtirb.Edge.Type.Return)))
        self.assertEqual(free_arguments(module), ARGUMENTS - {"a0", "a1"})

        # jal zero, <next block>; then the same return.
        ir, module, (jump, ret), external = riscv_function("6f004000", "67800000")
        ir.cfg.add(gtirb.Edge(jump, ret, gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=True)))
        ir.cfg.add(gtirb.Edge(ret, external, gtirb.Edge.Label(gtirb.Edge.Type.Return)))
        self.assertEqual(free_arguments(module), ARGUMENTS - {"a0", "a1"})

    def test_block_scope_is_unchanged(self):
        ir, module, (block,), external = riscv_function("67008300")
        ir.cfg.add(gtirb.Edge(block, external, gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)))
        self.assertEqual(free_arguments(module, scope="block"), set())


if __name__ == "__main__":
    unittest.main()
