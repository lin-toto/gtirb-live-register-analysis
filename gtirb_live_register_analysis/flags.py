"""Intraprocedural flag liveness, independent of the producer's GPR masks."""
from collections import deque

import gtirb
from capstone import CS_GRP_JUMP, CS_GRP_RET, CS_OP_IMM


def analyze_flags(function, analyzer):
    semantics, abi, decoder = analyzer.semantics, analyzer.abi, analyzer.decoder
    all_flags = semantics.flag_mask
    if not all_flags or not hasattr(function, "get_entry_blocks"):
        return None
    blocks = set(function.get_all_blocks())
    entries = set(function.get_entry_blocks())
    decoded = {b: list(decoder.get_instructions(b)) for b in blocks}
    # Do not turn a partial decode into proof that an opaque instruction cannot
    # consume flags (notably embedded data and unsupported extensions).
    if any(sum(i.size for i in decoded[b]) != b.size for b in blocks):
        return {b.uuid: [all_flags] * len(decoded[b]) for b in blocks}
    effects = {b: [semantics.flag_effects(i) for i in decoded[b]] for b in blocks}
    successors = {b: set() for b in blocks}
    predecessors = {b: set() for b in blocks}
    unknown, continuations = set(), set()
    for block in blocks:
        last = decoded[block][-1] if decoded[block] else None
        edges = list(block.outgoing_edges)
        for edge in edges:
            if not edge.label:
                unknown.add(block)
                continue
            if edge.label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Return):
                continue
            if edge.target in blocks:
                successors[block].add(edge.target)
                predecessors[edge.target].add(block)
                if last is not None and abi.is_call_instruction(last):
                    continuations.add(edge.target)
            elif edge.label.type == gtirb.EdgeType.Branch and not edge.label.direct:
                unknown.add(block)
        # A missing target set cannot prove that an indirect jump is a tail
        # call rather than an intra-function computed jump.
        if last is not None and last.group(CS_GRP_JUMP) and not edges:
            if not any(op.type == CS_OP_IMM for op in last.operands):
                unknown.add(block)
    live = {b: [0] * len(decoded[b]) for b in blocks}
    queue, queued = deque(blocks), set(blocks)
    while queue:
        block = queue.popleft()
        queued.remove(block)
        old = live[block][0] if live[block] else all_flags
        out = all_flags if block in unknown else 0
        for target in successors[block]:
            out |= live[target][0] if live[target] else all_flags
        for index in reversed(range(len(decoded[block]))):
            insn = decoded[block][index]
            read, kill, _ = effects[block][index]
            if abi.is_call_instruction(insn) or insn.group(CS_GRP_RET):
                out = 0
            else:
                out = read | (out & ~kill)
            # Status flags are neither ABI arguments nor returned values.
            if ((index == 0 and block in entries | continuations) or
                    (index > 0 and abi.is_call_instruction(decoded[block][index - 1]))):
                out = 0
            live[block][index] = out
        if live[block] and live[block][0] != old:
            for source in predecessors[block] - queued:
                queue.append(source)
                queued.add(source)
    return {b.uuid: masks for b, masks in live.items()}
