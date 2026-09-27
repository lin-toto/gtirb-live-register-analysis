"""Local flag liveness with may-preserve summaries for known callees.

The ABI is not a clobber proof for an internal call: IPA register allocation
and assembly callees may carry flags across it. Summaries track reads before a
definition and flags not defined on every returning path. Ordinary external
calls still use the ABI boundary. No GPR/vector masks are changed here.
"""
from collections import deque

import gtirb
from capstone import CS_GRP_RET, CS_OP_IMM


def _internal(block, module):
    return (isinstance(block, gtirb.CodeBlock) and block.module is module and
            block.section is not None and
            block.section.name not in (".plt", ".plt.got", ".plt.sec", ".iplt"))


class _FlagGraph:
    def __init__(self, module, analyzer, blocks):
        self.module = module
        self.all_flags = analyzer.semantics.flag_mask
        self.decoded = {b: list(analyzer.decoder.get_instructions(b))
                        for b in blocks}
        self.effects = {b: [analyzer.semantics.flag_effects(i)[:2] for i in insns]
                        for b, insns in self.decoded.items()}
        self.calls = {}
        self.successors = {b: set() for b in self.decoded}
        self.opaque = set()
        self.returns = set()
        self.external_exits = set()
        dependencies = {b: set() for b in self.decoded}
        for block, insns in self.decoded.items():
            if not insns or sum(i.size for i in insns) != block.size:
                self.opaque.add(block)
            edges = list(block.outgoing_edges)
            for index, insn in enumerate(insns):
                if not analyzer.abi.is_call_instruction(insn):
                    continue
                # None = incomplete direct-call target information (not a
                # clobber proof); () = ABI call; otherwise known local targets.
                targets = None
                if not any(op.type == CS_OP_IMM for op in insn.operands):
                    targets = ()
                elif index == len(insns) - 1:
                    calls = [e for e in edges if e.label and
                             e.label.type == gtirb.EdgeType.Call]
                    if calls:
                        if all(e.label.direct and _internal(e.target, module) for e in calls):
                            targets = tuple(e.target for e in calls)
                        else:
                            targets = ()
                self.calls[block, index] = targets
                if targets:
                    dependencies[block].update(targets)
            if insns and insns[-1].group(CS_GRP_RET):
                self.returns.add(block)
                continue
            for edge in edges:
                if edge.label is None:
                    self.opaque.add(block)
                elif edge.label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Return):
                    continue
                elif _internal(edge.target, module):
                    self.successors[block].add(edge.target)
                elif edge.label.type == gtirb.EdgeType.Branch and not edge.label.direct:
                    self.opaque.add(block)
                else:
                    self.external_exits.add(block)
            if not self.successors[block] and block not in self.external_exits:
                # Missing CFG or an unresolved computed branch is not evidence
                # of a definition, including opaque/non-returning instructions.
                self.opaque.add(block)
            dependencies[block].update(self.successors[block])
        self.predecessors = {b: set() for b in self.decoded}
        for block, targets in dependencies.items():
            for target in targets:
                self.predecessors[target].add(block)
        # Greatest fixed point for may-preserve: recursion or nontermination
        # cannot manufacture a proof that every path overwrites a flag. Once
        # stable, reads-before-definition use a least fixed point.
        self.preserve = self._solve(preservation=True)
        self.read = self._solve(preservation=False)

    def call_effect(self, block, index, reads=None, preserves=None):
        targets = self.calls[block, index]
        if targets is None:
            return self.all_flags, self.all_flags
        reads = self.read if reads is None else reads
        preserves = self.preserve if preserves is None else preserves
        read = preserve = 0
        for target in targets:
            read |= reads.get(target, 0)
            preserve |= preserves[target]
        return read, preserve

    def _solve(self, *, preservation):
        values = {b: self.all_flags if preservation else 0 for b in self.decoded}
        queue, queued = deque(self.decoded), set(self.decoded)
        while queue:
            block = queue.popleft()
            queued.remove(block)
            out = self.all_flags if (block in self.opaque or
                                     preservation and block in self.returns) else 0
            for target in self.successors[block]:
                out |= values[target]
            if block not in self.opaque:
                for index in reversed(range(len(self.decoded[block]))):
                    if (block, index) in self.calls:
                        read, preserve = self.call_effect(
                            block, index, reads={} if preservation else values,
                            preserves=values if preservation else self.preserve)
                        out = out & preserve if preservation else read | (out & preserve)
                    else:
                        read, kill = self.effects[block][index]
                        out = out & ~kill if preservation else read | (out & ~kill)
            if values[block] != out:
                values[block] = out
                for source in self.predecessors[block] - queued:
                    queue.append(source)
                    queued.add(source)
        return values


def analyze_flags(function, analyzer):
    all_flags = analyzer.semantics.flag_mask
    if not all_flags or not hasattr(function, "get_entry_blocks"):
        return None
    blocks = set(function.get_all_blocks())
    entries = set(function.get_entry_blocks()) & blocks
    if not blocks:
        return {}
    module = next(iter(blocks)).module
    graph = getattr(analyzer, "_flag_graph", None)
    if graph is None or graph.module is not module or not blocks.issubset(graph.decoded):
        graph = analyzer._flag_graph = _FlagGraph(
            module, analyzer, module.code_blocks if module is not None else blocks)
    decoded = graph.decoded
    successors = {b: graph.successors[b] & blocks for b in blocks}
    predecessors = {b: set() for b in blocks}
    for block, targets in successors.items():
        for target in targets:
            predecessors[target].add(block)

    # Forward may-unwritten analysis. A leaf's unchanged input flags can still
    # be observed by an IPA caller: preserve those bits at its return/tail exit.
    unwritten = {b: None for b in blocks}
    exit_flags = {}
    queue, queued = deque(entries), set(entries)
    for entry in entries:
        unwritten[entry] = all_flags
    while queue:
        block = queue.popleft()
        queued.remove(block)
        out = unwritten[block]
        if block not in graph.opaque:
            for index, (_, kill) in enumerate(graph.effects[block]):
                if (block, index) in graph.calls:
                    out &= graph.call_effect(block, index)[1]
                else:
                    out &= ~kill
        exit_flags[block] = out
        for target in successors[block]:
            old = unwritten[target]
            new = out if old is None else old | out
            if old != new:
                unwritten[target] = new
                if target not in queued:
                    queue.append(target)
                    queued.add(target)

    live = {b: [0] * len(decoded[b]) for b in blocks}
    queue, queued = deque(blocks), set(blocks)
    while queue:
        block = queue.popleft()
        queued.remove(block)
        old = live[block][0] if live[block] else all_flags
        out = all_flags if block in graph.opaque or unwritten[block] is None else 0
        outside = graph.successors[block] - blocks
        if block in graph.returns or block in graph.external_exits or outside:
            out |= exit_flags.get(block, all_flags)
        for target in successors[block]:
            out |= live[target][0] if live[target] else all_flags
        for target in outside:
            out |= graph.read[target]
        for index in reversed(range(len(decoded[block]))):
            if block in graph.opaque:
                out = all_flags
            elif (block, index) in graph.calls:
                read, preserve = graph.call_effect(block, index)
                out = read | (out & preserve)
            else:
                read, kill = graph.effects[block][index]
                out = read | (out & ~kill)
            live[block][index] = out
        if live[block] and live[block][0] != old:
            for source in predecessors[block] - queued:
                queue.append(source)
                queued.add(source)
    return {b.uuid: masks for b, masks in live.items()}
