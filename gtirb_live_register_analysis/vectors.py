"""Intraprocedural SysV x64 vector liveness for checkpoint state selection.

The producer currently exports GPR/flag masks only. This analysis does not
modify those masks or the register allocator. Bits describe the low 128,
next 128 and high 256 bits of each vector register, followed by mask registers.
None means that the entire function requires a full state snapshot.
"""
from collections import deque

import gtirb
from capstone import CsError, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_OP_IMM, CS_OP_REG


XMM0_7 = sum(1 << n for n in range(8))
XMM0_1 = 3
_PACKED_WRITES = {
    'movaps', 'movups', 'movapd', 'movupd', 'movdqa', 'movdqu', 'movd', 'movq',
    'pxor', 'pand', 'pandn', 'por', 'xorps', 'xorpd', 'andps', 'andpd',
    'andnps', 'andnpd', 'orps', 'orpd', 'addps', 'addpd', 'subps', 'subpd',
    'mulps', 'mulpd', 'divps', 'divpd', 'paddb', 'paddw', 'paddd', 'paddq',
    'psubb', 'psubw', 'psubd', 'psubq', 'pcmpeqb', 'pcmpeqw', 'pcmpeqd',
    'punpcklbw', 'punpcklwd', 'punpckldq', 'punpcklqdq', 'punpckhbw',
    'punpckhwd', 'punpckhdq', 'punpckhqdq', 'pshufd', 'pshuflw', 'pshufhw',
    'shufps', 'shufpd', 'unpcklps', 'unpcklpd', 'unpckhps', 'unpckhpd',
}


def vector_mask(name):
    for prefix, lanes in (('xmm', 1), ('ymm', 2), ('zmm', 3)):
        if name.startswith(prefix) and name[len(prefix):].isdigit():
            index = int(name[len(prefix):])
            return sum(1 << (index + 32 * lane) for lane in range(lanes))
    if name.startswith('k') and name[1:].isdigit():
        return 1 << (96 + int(name[1:]))
    return 0


def checkpoint_case(mask):
    """0: integer, 1: XMM0--7, 2: full (including unknown)."""
    if mask is None or mask & ~XMM0_7:
        return 2
    return int(bool(mask))


def _effects(insn):
    reads, writes = insn.regs_access()
    read_names = [insn.reg_name(r) for r in reads]
    write_names = [insn.reg_name(r) for r in writes]
    op = insn.mnemonic.split()[-1]
    # x87/MMX and explicit environment manipulation are not modeled as vector
    # lanes. Do not reduce checkpoints in these functions. EVEX masked writes
    # need a lane-aware model; conservatively retain their whole state too.
    if (insn.bytes[0] == 0x62 or op.startswith(('f', 'xsave', 'xrstor'))
            or op in {'ldmxcsr', 'stmxcsr', 'vldmxcsr', 'vstmxcsr', 'syscall',
                      'sysenter', 'int', 'int1', 'int3', 'iret', 'iretq', 'emms'}
            or any(n.startswith(('st', 'mm')) for n in read_names + write_names)):
        return None
    read = kill = 0
    for name in read_names:
        read |= vector_mask(name)
    vex = insn.bytes[0] in (0xc4, 0xc5)
    base_op = op[1:] if vex else op
    for name in write_names:
        # Unrecognized or partial writes never prove the old value dead. In
        # particular legacy MOVSS/MOVSD and PINSR preserve destination lanes.
        if base_op in _PACKED_WRITES:
            kill |= vector_mask(name)
            if vex and name.startswith(('xmm', 'ymm')):
                kill |= vector_mask('zmm' + name[3:])
    operands = insn.operands
    sources = operands[1:] if vex else operands
    if (base_op in {'pxor', 'xorps', 'xorpd'} and len(sources) == 2
            and all(o.type == CS_OP_REG for o in sources) and sources[0].reg == sources[1].reg):
        read = 0  # Proven dependency-breaking zero idiom.
    if op in ('vzeroall', 'vzeroupper'):
        kill = sum(vector_mask('zmm' + str(n)) for n in range(16))
        if op == 'vzeroupper':
            kill &= ~((1 << 32) - 1)
        read = 0
    return read, kill


def extended_state_clobbers(module, decoder):
    """Blocks that can speculate into unmodeled x87/environment state.

    Vector values are ABI caller-saved, but an interrupted internal callee may
    leave e.g. a nonempty x87 stack. Reachability here (including internal
    calls) is intentionally separate from intraprocedural vector liveness.
    External/PLT calls stop simulation and are not traversed.
    """
    blocks = {b for b in module.code_blocks if b.section.name == '.text'}
    unsafe = set()
    predecessors = {b: set() for b in blocks}
    for block in blocks:
        try:
            instructions = list(decoder.get_instructions(block))
            if (sum(i.size for i in instructions) != block.size or
                    any(_effects(i) is None for i in instructions) or
                    any(i.group(CS_GRP_CALL) and
                        not any(o.type == CS_OP_IMM for o in i.operands) for i in instructions)):
                unsafe.add(block)
        except (CsError, ValueError):
            unsafe.add(block)
        for edge in block.outgoing_edges:
            if (edge.target in blocks and edge.label and
                    edge.label.type != gtirb.EdgeType.Return):
                predecessors[edge.target].add(block)
    queue = deque(unsafe)
    while queue:
        for source in predecessors[queue.popleft()] - unsafe:
            unsafe.add(source)
            queue.append(source)
    return {b.uuid for b in unsafe}


def analyze_vectors(function, decoder, masks):
    """Return pre-instruction lane masks by block UUID, or None if unproven.

    ``masks`` is the validated producer table. Its contents do not model vector
    state, but absent instruction entries must not become a dead-state proof.
    Calls kill vector state, reading only ABI arguments; returns read XMM0--1.
    Wider-register functions conservatively use equally wide ABI arguments and
    results. Resolved in-function jump tables participate in the fixed point.
    """
    if masks is None:
        return None
    blocks = set(function.get_all_blocks())
    try:
        decoded = {b: list(decoder.get_instructions(b)) for b in blocks}
        if any(not decoded[b] or b.address is None or
               sum(i.size for i in decoded[b]) != b.size or
               any(gtirb.Offset(b, i.address-b.address) not in masks for i in decoded[b])
               for b in blocks):
            return None
        effects = {b: [_effects(i) for i in decoded[b]] for b in blocks}
    except (CsError, ValueError):
        return None
    if any(e is None for values in effects.values() for e in values):
        return None
    lanes = 1
    for values in decoded.values():
        for insn in values:
            # VEX-XMM writes zero upper lanes; that fact alone must not imply
            # the function takes 256-bit arguments or returns a 256-bit value.
            reads, writes = insn.regs_access()
            if any(insn.reg_name(r).startswith('ymm') for r in (*reads, *writes)):
                lanes = 2
    args = sum(XMM0_7 << (32*n) for n in range(lanes))
    returns = sum(XMM0_1 << (32*n) for n in range(lanes))
    successors = {b: set() for b in blocks}
    predecessors = {b: set() for b in blocks}
    tails = set()
    for block in blocks:
        last = decoded[block][-1]
        edges = list(block.outgoing_edges)
        for edge in edges:
            if edge.label is None:
                return None
            if edge.label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Return):
                continue
            if edge.target in blocks:
                successors[block].add(edge.target)
                predecessors[edge.target].add(block)
            elif edge.label.type == gtirb.EdgeType.Branch and edge.label.direct:
                tails.add(block)
            else:
                return None  # Unresolved indirect jump or broken fallthrough.
        if not edges and last.group(CS_GRP_JUMP):
            if not any(o.type == CS_OP_IMM for o in last.operands):
                return None
            tails.add(block)
        if not edges and not (last.group(CS_GRP_RET) or last.group(CS_GRP_JUMP)):
            return None
    live = {b: [0] * len(decoded[b]) for b in blocks}
    queue, queued = deque(blocks), set(blocks)
    while queue:
        block = queue.popleft()
        queued.remove(block)
        old = live[block][0]
        out = args if block in tails else 0
        for target in successors[block]:
            out |= live[target][0]
        for index in reversed(range(len(decoded[block]))):
            insn = decoded[block][index]
            read, kill = effects[block][index]
            if insn.group(CS_GRP_CALL):
                out = args
            elif insn.group(CS_GRP_RET):
                out = returns
            else:
                out = read | (out & ~kill)
            live[block][index] = out
        if old != live[block][0]:
            for source in predecessors[block] - queued:
                queue.append(source)
                queued.add(source)
    return {b.uuid: values for b, values in live.items()}
