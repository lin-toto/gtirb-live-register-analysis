import uuid

import gtirb
from gtirb_functions import Function
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting.assembly import Register

from .abi import AnalysisAwareABI

from capstone_gt import CsInsn
from collections import deque
from typing import Optional, List, Dict, Set


class LiveRegisterAnalyzer:
    abi: AnalysisAwareABI
    decoder: GtirbInstructionDecoder
    analysis_scope: str

    function: Function
    queue: deque
    in_regs: Dict[uuid.UUID, List[Set[Register]]]

    def __init__(self, abi: AnalysisAwareABI, decoder: GtirbInstructionDecoder, *,
                 analysis_scope: str = "function"):
        self.abi = abi
        self.decoder = decoder

        assert analysis_scope in ("function", "block")
        self.analysis_scope = analysis_scope

    def analyze(self, function: Function) -> Dict[uuid.UUID, List[Set[Register]]]:
        self.function = function
        self.queue = deque()
        self.in_regs = dict()

        init_blocks = function.get_exit_blocks() if self.analysis_scope == "function" \
                else function.get_all_blocks()
        for block in init_blocks:
            self.queue.append((block, None, None))

        while len(self.queue) > 0:
            block, instructions, instruction_idx = self.queue.popleft()
            if block not in function.get_all_blocks():
                continue

            if instruction_idx is None:
                instructions = list(self.decoder.get_instructions(block))
                instruction_idx = len(instructions) - 1
            self._analyze_step(block, instructions, instruction_idx)

        return self.in_regs

    def _analyze_step(self, block: gtirb.CodeBlock, instructions: List[CsInsn], instruction_idx: int):
        instruction = instructions[instruction_idx]

        if self.analysis_scope == "function":
            if block in self.function.get_exit_blocks() and instruction_idx == len(instructions) - 1:
                # is return instruction
                out_regs = self.abi.return_registers().union(self.abi.callee_saved_registers())
            else:
                if instruction_idx == len(instructions) - 1:
                    successors = [(e.target, list(self.decoder.get_instructions(e.target)), 0) \
                        for e in block.outgoing_edges if isinstance(e.target, gtirb.CodeBlock)]
                else:
                    successors = [(block, instructions, instruction_idx + 1)]
                out_regs = set().union(*[self._get_in_regs(*x) for x in successors])
        elif self.analysis_scope == "block":
            if instruction_idx == len(instructions) - 1:
                out_regs = set(self.abi.all_registers())
            else:
                out_regs = self._get_in_regs(block, instructions, instruction_idx + 1)
        else:
            raise NotImplementedError

        gen_regs = self._instruction_regs_read(instruction)
        kill_regs = self._instruction_regs_write(instruction).difference(gen_regs)
        in_regs = gen_regs.union(out_regs.difference(kill_regs))
        changed = self._set_in_regs(block, instructions, instruction_idx, in_regs)

        if changed:
            if instruction_idx == 0 and self.analysis_scope == "function":
                if block not in self.function.get_entry_blocks():
                    for e in block.incoming_edges:
                        if e.label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Return):
                            continue

                        source_instructions = list(self.decoder.get_instructions(e.source))
                        self.queue.append((e.source, source_instructions, len(source_instructions) - 1))
            else:
                self.queue.append((block, instructions, instruction_idx - 1))

    def _instruction_regs_read(self, instruction: CsInsn) -> Set[Register]:
        regs_read = self._reg_ids_to_registers(instruction, instruction.regs_access()[0])
        # TODO: handle call properly
        if instruction.mnemonic == "call":
            regs_read = regs_read.union(self.abi.calling_convention_registers())

        return regs_read

    def _instruction_regs_write(self, instruction: CsInsn) -> Set[Register]:
        if instruction.mnemonic.startswith("cmov"):
            return set()

        regs_write = self._reg_ids_to_registers(instruction, instruction.regs_access()[1])
        # if instruction.mnemonic == "call":
        #    regs_write = regs_write.union(self.abi.caller_saved_registers())

        return regs_write

    def _reg_ids_to_registers(self, instruction: CsInsn, reg_ids: List[int]) -> Set[Register]:
        return set([self.abi.get_register(instruction.reg_name(x)) for x in reg_ids
                    if instruction.reg_name(x) in self.abi._register_map])

    def _get_in_regs(self, block: gtirb.CodeBlock, instructions: List[CsInsn], instruction_idx: int) -> Set[Register]:
        if block.uuid not in self.in_regs:
            self.in_regs[block.uuid] = [set()] * len(instructions)
        return self.in_regs[block.uuid][instruction_idx]

    def _set_in_regs(self, block: gtirb.CodeBlock, instructions: List[CsInsn], instruction_idx: int,
                     in_regs: Set[Register]) -> bool:
        old_in_regs = self._get_in_regs(block, instructions, instruction_idx)
        self.in_regs[block.uuid][instruction_idx] = in_regs

        return old_in_regs != in_regs