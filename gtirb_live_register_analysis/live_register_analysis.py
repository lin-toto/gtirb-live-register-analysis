import functools
import uuid

import gtirb
from gtirb_functions import Function
from gtirb_capstone.instructions import GtirbInstructionDecoder

from gtirb_live_register_analysis.isa.x64 import X64
from gtirb_live_register_analysis.utils.instruction_decoder import CachedGtirbInstructionDecoder

from capstone_gt import CsInsn
from collections import defaultdict, deque
from typing import Optional, List, Dict, Set


class LiveRegisterAnalysis:
    # TODO: support different ISAs
    ISA = X64

    decoder: GtirbInstructionDecoder

    function: Function
    queue: deque
    in_regs: Dict[uuid.UUID, List[Set[str]]]

    def __init__(self, isa: gtirb.Module.ISA, decoder: Optional[GtirbInstructionDecoder] = None):
        if decoder is None:
            decoder = CachedGtirbInstructionDecoder(isa)
        self.decoder = decoder

    def analyze(self, function: Function) -> Dict[uuid.UUID, List[Set[str]]]:
        self.function = function
        self.queue = deque()
        self.in_regs = dict()

        for block in function.get_exit_blocks():
            self.queue.append((block, None, None))

        while len(self.queue) > 0:
            block, instructions, instruction_idx = self.queue.popleft()
            if instruction_idx is None:
                instructions = list(self.decoder.get_instructions(block))
                instruction_idx = len(instructions) - 1
            self._analyze_step(block, instructions, instruction_idx)

        return self.in_regs

    def _analyze_step(self, block: gtirb.CodeBlock, instructions: List[CsInsn], instruction_idx: int):
        instruction = instructions[instruction_idx]

        if block in self.function.get_exit_blocks() and instruction_idx == len(instructions) - 1:
            # is return instruction
            out_regs = self.ISA.RETURN_REGISTERS.union(self.ISA.CALLEE_PRESERVED_REGISTERS)
        else:
            if instruction_idx == len(instructions) - 1:
                successors = [(e.target, list(self.decoder.get_instructions(e.target)), 0) for e in block.outgoing_edges]
            else:
                successors = [(block, instructions, instruction_idx + 1)]
            out_regs = set().union(*[self._get_in_regs(*x) for x in successors])

        gen_regs = self._reg_ids_to_full_name(instruction, instruction.regs_access()[0])
        kill_regs = self._reg_ids_to_full_name(instruction, instruction.regs_access()[1]).difference(gen_regs)
        in_regs = gen_regs.union(out_regs.difference(kill_regs))
        changed = self._set_in_regs(block, instructions, instruction_idx, in_regs)

        if changed:
            if instruction_idx == 0:
                if block not in self.function.get_entry_blocks():
                    for e in block.incoming_edges:
                        source_instructions = list(self.decoder.get_instructions(e.source))
                        self.queue.append((e.source, source_instructions, len(source_instructions) - 1))
            else:
                self.queue.append((block, instructions, instruction_idx - 1))

    def _reg_ids_to_full_name(self, instruction: CsInsn, reg_ids: List[int]) -> set:
        return set([self.ISA.FULL_REGISTERS_MAP[instruction.reg_name(x)] for x in reg_ids])

    def _get_in_regs(self, block: gtirb.CodeBlock, instructions: List[CsInsn], instruction_idx: int) -> Set[str]:
        if block.uuid not in self.in_regs:
            self.in_regs[block.uuid] = [set()] * len(instructions)
        return self.in_regs[block.uuid][instruction_idx]

    def _set_in_regs(self, block: gtirb.CodeBlock, instructions: List[CsInsn], instruction_idx: int, in_regs: set) -> bool:
        old_in_regs = self._get_in_regs(block, instructions, instruction_idx)
        self.in_regs[block.uuid][instruction_idx] = in_regs

        return old_in_regs != in_regs
