import unittest
from uuid import uuid4

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.abis import _X86_64_ELF, _ARM64_ELF


def fixture(isa, abi, parts):
    module = gtirb.Module(name='flags', isa=isa, file_format=gtirb.Module.FileFormat.ELF,
                          byte_order=gtirb.Module.ByteOrder.Little)
    ir = gtirb.IR(modules=[module])
    section = gtirb.Section(name='.text', module=module)
    code = [bytes.fromhex(p) for p in parts]
    interval = gtirb.ByteInterval(address=0x1000, contents=b''.join(code), section=section)
    blocks, offset = [], 0
    for part in code:
        blocks.append(gtirb.CodeBlock(size=len(part), offset=offset, byte_interval=interval))
        offset += len(part)
    function = Function(uuid4(), {blocks[0]}, set(blocks), exitBlocks={blocks[-1]})
    registers = list(abi.all_registers())
    module.aux_data['liveRegisterNames'] = gtirb.AuxData(
        [r.name for r in registers], 'sequence<string>')
    module.aux_data['liveRegisterSets'] = gtirb.AuxData({}, 'mapping<Offset,uint64_t>')
    manager = LiveRegisterManager(module, abi)
    # Producer says every register is live: the merge may change ONLY flags.
    module.aux_data['liveRegisterSets'].data.update({gtirb.Offset(b, i.address-b.address):
        (1 << len(registers))-1 for b in blocks for i in manager.analyzer.decoder.get_instructions(b)})
    return ir, module, blocks, function, manager


class IntraproceduralFlagsTests(unittest.TestCase):
    def check(self, isa, abi, code, expected):
        ir, module, (block,), function, manager = fixture(isa, abi, [code])
        manager.analyze(function)
        values = manager.result_cache[function.uuid][block.uuid]
        self.assertEqual([abi.flag_register() in v for v in values], expected)
        for value in values:
            self.assertEqual(value - {abi.flag_register()},
                             set(abi.all_registers()) - {abi.flag_register()})
        conservative = LiveRegisterManager(module, abi, conservative_flags=True)
        conservative.analyze(function)
        self.assertTrue(all(abi.flag_register() in v
                            for v in conservative.result_cache[function.uuid][block.uuid]))

    def test_per_flag_definitions_and_reads(self):
        for code, expected in (
                ('90 48 ff c0 0f 90 c0 c3', [False, False, True, False]), # INC kills OF
                ('90 48 ff c0 0f 92 c0 c3', [False, True, True, False]),  # but keeps CF
                ('90 48 85 c0 9f c3', [False, False, True, False]),       # AF undefined kills
                ('90 fc a4 c3', [False, False, False, False]),           # DF is not arithmetic
                ('90 48 d3 e0 0f 92 c0 c3', [False, True, True, False])): # CL may be zero
            self.check(gtirb.Module.ISA.X64, _X86_64_ELF(), code, expected)

    def test_aarch64_nzcv(self):
        # nop; cmp x0,x1; cset x0,eq; ret
        self.check(gtirb.Module.ISA.ARM64, _ARM64_ELF(),
                   '1f2003d5 1f0001eb e0179f9a c0035fd6', [False, False, True, False])
        # nop; ccmp x0,x1,#0,eq; cset x0,eq; ret (conditional compare also reads NZCV)
        self.check(gtirb.Module.ISA.ARM64, _ARM64_ELF(),
                   '1f2003d5 000041fa e0179f9a c0035fd6', [False, True, True, False])
        # nop; msr nzcv,x0; cset x0,eq; ret
        self.check(gtirb.Module.ISA.ARM64, _ARM64_ELF(),
                   '1f2003d5 00421bd5 e0179f9a c0035fd6', [False, False, True, False])

    def test_calls_tails_and_unknown_indirects(self):
        for isa, abi, call, use_ret, indirect, direct in (
                (gtirb.Module.ISA.X64, _X86_64_ELF(), '90 e800000000', '0f92c0 c3',
                 '90 ffe0', '90 e900000000'),
                (gtirb.Module.ISA.ARM64, _ARM64_ELF(), '1f2003d5 00000094', 'e0179f9a c0035fd6',
                 '1f2003d5 00001fd6', '1f2003d5 00000014')):
            ir, module, blocks, function, manager = fixture(isa, abi, [call, use_ret])
            external = gtirb.ProxyBlock(module=module)
            ir.cfg.add(gtirb.Edge(blocks[0], external, gtirb.Edge.Label(gtirb.EdgeType.Call)))
            ir.cfg.add(gtirb.Edge(blocks[0], blocks[1], gtirb.Edge.Label(gtirb.EdgeType.Fallthrough)))
            manager.analyze(function)
            self.assertTrue(all(abi.flag_register() not in v for b in blocks
                                for v in manager.result_cache[function.uuid][b.uuid]))
            for code, is_direct in ((indirect, False), (direct, True)):
                ir, module, (block,), function, manager = fixture(isa, abi, [code])
                external = gtirb.ProxyBlock(module=module)
                ir.cfg.add(gtirb.Edge(block, external,
                    gtirb.Edge.Label(gtirb.EdgeType.Branch, direct=is_direct)))
                manager.analyze(function)
                self.assertEqual(abi.flag_register() in
                                 manager.result_cache[function.uuid][block.uuid][-1], not is_direct)


if __name__ == '__main__':
    unittest.main()
