"""Local flag liveness in which every call and return is an ABI boundary.

Neither the x86-64 psABI nor AAPCS64 preserves the arithmetic flags or NZCV
across a call. So a call kills them, and nothing is live into a return or into a
tail transfer out of the program. Compiled code does not read flags across a
call: a scan of about 114,000 direct internal calls in the SPEC CPU2006 integer,
libhtp and jsmn lifts found none. Flags stay precise per flag. A branch into
another function's blocks, such as GCC's .cold parts, still uses the target's
reads before its definitions. A missing CFG or an unresolved computed branch
still keeps every flag live. No GPR/vector masks are changed here.

DDisasm's masks follow the same rule when they carry the liveRegisterFlagRule
"call-boundary". This analysis recomputes the flags for other masks, such as
those of older lifts, and for the Python analysis.
"""
from collections import deque

import gtirb
from capstone import CS_GRP_RET


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
        self.calls = set()
        self.successors = {b: set() for b in self.decoded}
        self.opaque = set()
        self.returns = set()
        self.external_exits = set()
        for block, insns in self.decoded.items():
            if not insns or sum(i.size for i in insns) != block.size:
                self.opaque.add(block)
            edges = list(block.outgoing_edges)
            for index, insn in enumerate(insns):
                if analyzer.abi.is_call_instruction(insn):
                    self.calls.add((block, index))
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
        self.predecessors = {b: set() for b in self.decoded}
        for block, targets in self.successors.items():
            for target in targets:
                self.predecessors[target].add(block)
        self.read = self._reads_before_definition()

    def live_before(self, block, index, out):
        """Flags live before instruction `index` of `block`, given those live after it."""
        if (block, index) in self.calls:
            return 0
        read, kill = self.effects[block][index]
        return read | (out & ~kill)

    def _reads_before_definition(self):
        values = {b: 0 for b in self.decoded}
        queue, queued = deque(self.decoded), set(self.decoded)
        while queue:
            block = queue.popleft()
            queued.remove(block)
            out = self.all_flags if block in self.opaque else 0
            for target in self.successors[block]:
                out |= values[target]
            if block not in self.opaque:
                for index in reversed(range(len(self.decoded[block]))):
                    out = self.live_before(block, index, out)
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

    # A block no entry reaches has no proof of a definition: keep every flag live.
    reached, queue = set(entries), deque(entries)
    while queue:
        for target in successors[queue.popleft()]:
            if target not in reached:
                reached.add(target)
                queue.append(target)

    live = {b: [0] * len(decoded[b]) for b in blocks}
    queue, queued = deque(blocks), set(blocks)
    while queue:
        block = queue.popleft()
        queued.remove(block)
        old = live[block][0] if live[block] else all_flags
        out = all_flags if block in graph.opaque or block not in reached else 0
        for target in successors[block]:
            out |= live[target][0] if live[target] else all_flags
        for target in graph.successors[block] - blocks:
            out |= graph.read[target]
        for index in reversed(range(len(decoded[block]))):
            out = all_flags if block in graph.opaque else graph.live_before(block, index, out)
            live[block][index] = out
        if live[block] and live[block][0] != old:
            for source in predecessors[block] - queued:
                queue.append(source)
                queued.add(source)
    return {b.uuid: masks for b, masks in live.items()}
