import unittest

import gtirb
from gtirb_live_register_analysis.abis import _X86_64_ELF
from gtirb_live_register_analysis.vectors import (
    analyze_vectors, checkpoint_case, vector_mask, extended_state_clobbers)
from test_intraprocedural_flags import fixture
from gtirb_live_register_analysis.manager import VECTOR_REGISTER_NAMES


class VectorLivenessTests(unittest.TestCase):
    def test_producer_words_are_validated_and_projected_without_python(self):
        ir, module, (block,), fn, manager = self.analyze(['90 c3'])
        scalar = [r.name for r in manager.abi.all_registers() if r.name not in VECTOR_REGISTER_NAMES]
        names = scalar + list(VECTOR_REGISTER_NAMES)
        module.aux_data['liveRegisterNames'].data = names
        low = module.aux_data['liveRegisterSets'].data
        high = module.aux_data['liveRegisterSetsHigh'] = gtirb.AuxData({}, 'mapping<Offset,uint64_t>')
        off = gtirb.Offset(block, 0)
        for selected in ((), ('xmm0',), ('xmm31', 'ymm31h', 'zmm31h', 'k7')):
            mask = sum(1 << names.index(name) for name in selected)
            low[off], high.data[off] = mask & ((1 << 64)-1), mask >> 64
            manager.refresh(preserve_liveness=True)
            high = module.aux_data['liveRegisterSetsHigh']
            self.assertEqual(manager.analysis_source, 'ddisasm')
            self.assertEqual(manager.producer_vector_mask(block, 0),
                             sum(1 << VECTOR_REGISTER_NAMES.index(n) for n in selected))
            manager.analyze(fn)
            physical = manager.live_registers(fn, block, 0)
            for name in selected:
                self.assertIn(manager.abi.get_register(name[:-1] if name.endswith('h') else name), physical)
        high.data[off] = 1 << 64
        manager.refresh(preserve_liveness=True)
        self.assertIsNone(manager.producer_vector_mask(block, 0))
        self.assertEqual(manager.analysis_source, 'ddisasm')
        module.aux_data.pop('liveRegisterSetsHigh')
        manager.refresh(preserve_liveness=True)
        self.assertIsNone(manager.producer_vector_mask(block, 0))

    def analyze(self, parts):
        ir, module, blocks, fn, manager = fixture(gtirb.Module.ISA.X64, _X86_64_ELF(), parts)
        return ir, module, blocks, fn, manager

    def test_dead_live_and_high_vectors(self):
        # The returned low vectors are defined AFTER the insertion point. A
        # store before those definitions makes its source genuinely live.
        for code, expected in (
            ('90 660fefc0 660fefc9 c3', 0),
            ('90 0f2900 660fefc0 660fefc9 c3', 1),
            ('90 440f2900 660fefc0 660fefc9 c3', 2),
            ('90 c5fe7f00 660fefc0 660fefc9 c3', 2),
        ):
            ir, module, (b,), fn, mgr = self.analyze([code])
            values = analyze_vectors(fn, mgr.analyzer.decoder, mgr._metadata_sets)
            self.assertEqual(checkpoint_case(values[b.uuid][0]), expected, code)

    def test_partial_write_does_not_kill_live_lanes(self):
        # MOVSS xmm0,xmm1 retains the upper 96 bits of xmm0; the following
        # full-vector store observes them. A full MOVAPS defines all 128 bits.
        for move, live in [('f30f10c1', True), ('0f28c1', False)]:
            ir, module, (b,), fn, mgr = self.analyze([
                f'90 {move} 0f2900 660fefc0 660fefc9 c3'])
            values = analyze_vectors(fn, mgr.analyzer.decoder, mgr._metadata_sets)
            self.assertEqual(bool(values[b.uuid][0] & vector_mask('xmm0')), live)

    def test_call_kills_caller_saved_vectors_but_reads_arguments(self):
        ir, module, (call, continuation), fn, mgr = self.analyze([
            '90 e800000000', '440f2900 660fefc0 660fefc9 c3'])
        ir.cfg.add(gtirb.Edge(call, gtirb.ProxyBlock(module=module),
                             gtirb.Edge.Label(gtirb.EdgeType.Call)))
        ir.cfg.add(gtirb.Edge(call, continuation, gtirb.Edge.Label(gtirb.EdgeType.Fallthrough)))
        values = analyze_vectors(fn, mgr.analyzer.decoder, mgr._metadata_sets)
        self.assertEqual(values[call.uuid][-1], 255)
        self.assertTrue(values[continuation.uuid][0] & vector_mask('xmm8'))

    def test_cfg_fixed_point_and_missing_data(self):
        ir, module, (start, loop, end), fn, mgr = self.analyze([
            '90 eb00', '440f2900 7500', '660fefc0 660fefc9 c3'])
        for source, target, kind in ((start, loop, gtirb.EdgeType.Branch),
                                    (loop, loop, gtirb.EdgeType.Branch),
                                    (loop, end, gtirb.EdgeType.Fallthrough)):
            ir.cfg.add(gtirb.Edge(source, target, gtirb.Edge.Label(kind)))
        values = analyze_vectors(fn, mgr.analyzer.decoder, mgr._metadata_sets)
        self.assertEqual(checkpoint_case(values[start.uuid][0]), 2)
        mgr._metadata_sets.pop(gtirb.Offset(end, 0))
        self.assertIsNone(analyze_vectors(fn, mgr.analyzer.decoder, mgr._metadata_sets))

    def test_unknown_target_environment_and_partial_decode_are_full(self):
        for code in ('90 ffe0', '90 d9e8 c3', '90 0fae10 c3', '90 0f'):
            ir, module, (b,), fn, mgr = self.analyze([code])
            self.assertIsNone(analyze_vectors(fn, mgr.analyzer.decoder, mgr._metadata_sets))
        self.assertEqual(checkpoint_case(None), 2)

    def test_internal_x87_callee_is_not_confused_with_vector_abi_kills(self):
        ir, module, (caller, callee), fn, mgr = self.analyze(['90 e800000000', 'd9e8 c3'])
        ir.cfg.add(gtirb.Edge(caller, callee, gtirb.Edge.Label(gtirb.EdgeType.Call)))
        self.assertIn(caller.uuid, extended_state_clobbers(module, mgr.analyzer.decoder))
        ir.cfg.clear()
        ir.cfg.add(gtirb.Edge(caller, gtirb.ProxyBlock(module=module),
                             gtirb.Edge.Label(gtirb.EdgeType.Call)))
        self.assertNotIn(caller.uuid, extended_state_clobbers(module, mgr.analyzer.decoder))
        # An unknown call and a masked EVEX operation are not evidence of x87.
        for code in ('ffd0 c3', '62f17c4857c0 c3'):
            ir, module, (b,), fn, mgr = self.analyze([code])
            self.assertNotIn(b.uuid, extended_state_clobbers(module, mgr.analyzer.decoder))


if __name__ == '__main__':
    unittest.main()
