import unittest
from uuid import uuid4

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.abis import _X86_64_ELF, _ARM64_ELF
from gtirb_live_register_analysis.flags import analyze_flags


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
                ('90 48 ff c0 0f 90 c0 c3', [0, 0, 32, 0]), # INC kills OF; nothing lives into RET
                ('90 48 ff c0 0f 92 c0 c3', [1, 1, 1, 0]),  # CF passes through INC to the reader
                ('90 48 85 c0 9f c3', [0, 0, 31, 0]),       # AF undefined kills
                ('90 fc a4 c3', [0, 0, 0, 0]),              # DF is not arithmetic
                ('90 48 d3 e0 0f 92 c0 c3', [1, 1, 1, 0])): # CL may be zero: CF stays live
            self.check(gtirb.Module.ISA.X64, _X86_64_ELF(), code, list(map(bool, expected)))
            _, _, (block,), function, manager = fixture(
                gtirb.Module.ISA.X64, _X86_64_ELF(), [code])
            self.assertEqual(analyze_flags(function, manager.analyzer)[block.uuid], expected)

    def check_missing_flag_read(self, instruction, expected_read, expected_kill=None):
        # XOR defines the incoming flags. A clobbering patch at the NOP must
        # preserve them for the following reader, even if it also writes flags.
        code = f'31c0 90 {instruction} c3'
        self.check(gtirb.Module.ISA.X64, _X86_64_ELF(), code,
                   [False, True, True, False])
        ir, module, (block,), function, manager = fixture(
            gtirb.Module.ISA.X64, _X86_64_ELF(), [code])
        reader = list(manager.analyzer.decoder.get_instructions(block))[2]
        read, kill, _ = manager.analyzer.semantics.flag_effects(reader)
        self.assertEqual(read, expected_read, reader.mnemonic)
        if expected_kill is not None:
            self.assertEqual(kill, expected_kill, reader.mnemonic)

    def test_adox_preserves_unresolved_aggregate_read(self):
        self.check_missing_flag_read('f3480f38f6c1', 63)  # adox rax, rcx

    def test_rcl_reads_carry(self):
        self.check_missing_flag_read('48d1d0', 1)

    def test_rcr_reads_carry(self):
        self.check_missing_flag_read('48d1d8', 1)

    def test_cmc_reads_carry(self):
        self.check_missing_flag_read('f5', 1)

    def test_fcmov_reads_condition_without_killing_integer_flags(self):
        # CF=1, PF=2, ZF=8 in the six-bit arithmetic-flag mask. The x87
        # fpu_flags union must not masquerade as integer flag definitions.
        for code, mask in [('dac1', 1), ('dac9', 8), ('dad1', 9), ('dad9', 2),
                           ('dbc1', 1), ('dbc9', 8), ('dbd1', 9), ('dbd9', 2)]:
            with self.subTest(instruction=code):
                self.check_missing_flag_read(code, mask, expected_kill=0)

    def test_aarch64_nzcv(self):
        # nop; cmp x0,x1; cset x0,eq; ret
        self.check(gtirb.Module.ISA.ARM64, _ARM64_ELF(),
                   '1f2003d5 1f0001eb e0179f9a c0035fd6', [False, False, True, False])
        # nop; ccmp x0,x1,#0,eq; cset x0,eq; ret (conditional compare also reads NZCV)
        self.check(gtirb.Module.ISA.ARM64, _ARM64_ELF(),
                   '1f2003d5 000041fa e0179f9a c0035fd6', [True, True, True, False])
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
            masks = analyze_flags(function, manager.analyzer)
            self.assertEqual(masks[blocks[0].uuid], [0, 0])
            # A patch after the call must not clobber the continuation's read,
            # even though that dependency does not cross the external call.
            self.assertTrue(masks[blocks[1].uuid][0])
            self.assertEqual(masks[blocks[1].uuid][-1], 0)
            for code, is_direct in ((indirect, False), (direct, True)):
                ir, module, (block,), function, manager = fixture(isa, abi, [code])
                external = gtirb.ProxyBlock(module=module)
                ir.cfg.add(gtirb.Edge(block, external,
                    gtirb.Edge.Label(gtirb.EdgeType.Branch, direct=is_direct)))
                manager.analyze(function)
                # A direct tail call is an ABI boundary like any call; the
                # unresolved indirect branch stays all-live: nothing proves where it goes.
                live = abi.flag_register() in manager.result_cache[function.uuid][block.uuid][-1]
                self.assertEqual(live, not is_direct)

    def test_local_calls_kill_flags(self):
        # Neither the x86-64 psABI nor AAPCS64 preserves flags across a call, so
        # whatever the callee does, a flag produced before a local call is dead
        # after it, and nothing is live into a return.
        for isa, abi, compare, call, reader, nop, ret, partial in (
                (gtirb.Module.ISA.X64, _X86_64_ELF(), '4839c8', 'e800000000',
                 '0f92c0', '90', 'c3', '48ffc0'),
                (gtirb.Module.ISA.ARM64, _ARM64_ELF(), '1f0001eb', '00000094',
                 'e0179f9a', '1f2003d5', 'c0035fd6', '00040091')):
            for leaf in (nop, partial, compare):
                with self.subTest(isa=isa, leaf=leaf):
                    ir, module, blocks, _, manager = fixture(
                        isa, abi, [f'{compare} {nop} {call}', f'{reader} {ret}', f'{leaf} {ret}'])
                    caller = Function(uuid4(), {blocks[0]}, set(blocks[:2]), exitBlocks={blocks[1]})
                    callee = Function(uuid4(), {blocks[2]}, {blocks[2]}, exitBlocks={blocks[2]})
                    ir.cfg.add(gtirb.Edge(blocks[0], blocks[2], gtirb.Edge.Label(gtirb.EdgeType.Call)))
                    ir.cfg.add(gtirb.Edge(blocks[0], blocks[1], gtirb.Edge.Label(gtirb.EdgeType.Fallthrough)))
                    masks = analyze_flags(caller, manager.analyzer)
                    self.assertEqual(masks[blocks[0].uuid][-1], 0)
                    self.assertEqual(masks[blocks[0].uuid][-2], 0)
                    self.assertTrue(masks[blocks[1].uuid][0])
                    self.assertEqual(analyze_flags(callee, manager.analyzer)[blocks[2].uuid][-1], 0)

    def test_refresh_discards_cached_flag_effects(self):
        # nop -> clc (x64) or nop -> cmp x0, x1 (AArch64) before a flag reader.
        for isa, abi, before, writer, reader, ret in (
                (gtirb.Module.ISA.X64, _X86_64_ELF(), '90', 'f8', '0f92c0', 'c3'),
                (gtirb.Module.ISA.ARM64, _ARM64_ELF(), '1f2003d5', '1f0001eb', 'e0179f9a', 'c0035fd6')):
            with self.subTest(isa=isa):
                ir, module, (block,), function, manager = fixture(isa, abi, [f'{before} {reader} {ret}'])
                self.assertTrue(analyze_flags(function, manager.analyzer)[block.uuid][0])
                interval = block.byte_interval
                replacement = bytes.fromhex(writer)
                interval.contents = (interval.contents[:block.offset] + replacement +
                                     interval.contents[block.offset + len(replacement):])
                manager.refresh(preserve_liveness=True)
                self.assertFalse(analyze_flags(function, manager.analyzer)[block.uuid][0])

    def test_callees_do_not_carry_flags_on_any_path(self):
        for isa, abi, compare, call, reader, branch, nop, ret in (
                (gtirb.Module.ISA.X64, _X86_64_ELF(), '4839c8', 'e800000000',
                 '0f92c0', 'e300', '90', 'c3'),
                (gtirb.Module.ISA.ARM64, _ARM64_ELF(), '1f0001eb', '00000094',
                 'e0179f9a', '000000b4', '1f2003d5', 'c0035fd6')):
            ir, _, b, _, manager = fixture(isa, abi, [f'{compare} {nop} {call}',
                f'{reader} {ret}', branch, f'{compare} {ret}', f'{nop} {ret}'])
            for src, dst, kind in ((0, 2, gtirb.EdgeType.Call), (0, 1, gtirb.EdgeType.Fallthrough),
                                   (2, 3, gtirb.EdgeType.Branch), (2, 4, gtirb.EdgeType.Fallthrough)):
                ir.cfg.add(gtirb.Edge(b[src], b[dst], gtirb.Edge.Label(kind)))
            caller = Function(uuid4(), {b[0]}, set(b[:2]), exitBlocks={b[1]})
            callee = Function(uuid4(), {b[2]}, set(b[2:]), exitBlocks=set(b[3:]))
            self.assertEqual(analyze_flags(caller, manager.analyzer)[b[0].uuid][-1], 0)
            leaves = analyze_flags(callee, manager.analyzer)
            self.assertEqual(leaves[b[3].uuid][-1], 0)
            self.assertEqual(leaves[b[4].uuid][-1], 0)

    def test_internal_tail_and_recursive_calls(self):
        # A recursive call and a direct tail transfer into another function
        # both leave no flag live: the call kills them, and the tail target
        # reads none before its own definitions.
        ir, _, b, _, manager = fixture(gtirb.Module.ISA.X64, _X86_64_ELF(),
            ['e300', 'e800000000', 'c3', '90 c3', 'e900000000'])
        for src, dst, kind in ((0, 3, gtirb.EdgeType.Branch), (0, 1, gtirb.EdgeType.Fallthrough),
                               (1, 0, gtirb.EdgeType.Call), (1, 2, gtirb.EdgeType.Fallthrough),
                               (4, 0, gtirb.EdgeType.Branch)):
            ir.cfg.add(gtirb.Edge(b[src], b[dst], gtirb.Edge.Label(kind)))
        recursive = Function(uuid4(), {b[0]}, set(b[:4]), exitBlocks={b[2], b[3]})
        tail = Function(uuid4(), {b[4]}, {b[4]}, exitBlocks={b[4]})
        self.assertEqual(analyze_flags(recursive, manager.analyzer)[b[1].uuid], [0])
        self.assertEqual(analyze_flags(tail, manager.analyzer)[b[4].uuid], [0])


if __name__ == '__main__':
    unittest.main()
