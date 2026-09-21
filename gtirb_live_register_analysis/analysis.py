import uuid

import gtirb
from gtirb_functions import Function
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting.assembly import Register

from .abi import AnalysisAwareABI
from .arch import semantics_for_abi

from capstone import CS_AC_READ, CS_GRP_INT, CS_OP_MEM, CS_OP_REG, CsError, CsInsn
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
        self.semantics = semantics_for_abi(self)

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
                if not instructions:
                    self.in_regs[block.uuid] = []
                    continue
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
            elif instruction_idx > 0:
                self.queue.append((block, instructions, instruction_idx - 1))

    def _instruction_regs_read(self, instruction: CsInsn) -> Set[Register]:
        # System calls and software interrupts do not use the function ABI.
        if instruction.group(CS_GRP_INT):
            return set(self.abi.all_registers())
        try:
            regs_read = self._reg_ids_to_registers(instruction, instruction.regs_access()[0])
        except CsError:
            regs_read = self._instruction_regs_read_fallback(instruction)
        regs_read = regs_read.union(self._instruction_operand_regs_read(instruction))
        if self.semantics.needs_explicit_read_fallback(instruction):
            regs_read = regs_read.union(self._instruction_regs_read_fallback(instruction))
        if self.abi.is_call_instruction(instruction):
            regs_read = regs_read.union(self.abi.conservative_call_registers())

        return regs_read

    def _instruction_regs_write(self, instruction: CsInsn) -> Set[Register]:
        override = self.semantics.instruction_regs_write_override(instruction)
        if override is not None:
            return override

        try:
            return self._instruction_regs_write_capstone(instruction)
        except CsError:
            return self._instruction_regs_write_fallback(instruction)

    def _instruction_regs_write_capstone(self, instruction: CsInsn) -> Set[Register]:
        regs_write = set()
        for reg_id in instruction.regs_access()[1]:
            reg_name = instruction.reg_name(reg_id)
            if self.semantics.ignore_register_name(reg_name) or reg_name not in self.abi._register_map:
                continue
            
            reg = self.abi.get_register(reg_name)
            if not self.semantics.register_write_kills(instruction, reg, reg_name):
                continue

            regs_write.add(reg)

        return regs_write

    def _reg_ids_to_registers(self, instruction: CsInsn, reg_ids: List[int]) -> Set[Register]:
        return {
            reg
            for reg in (
                self._reg_name_to_register(instruction.reg_name(x))
                for x in reg_ids
            )
            if reg is not None
        }

    def _reg_name_to_register(self, reg_name: str) -> Optional[Register]:
        if self.semantics.ignore_register_name(reg_name):
            return None
        if reg_name not in self.abi._register_map:
            return None
        return self.abi.get_register(reg_name)

    def _instruction_operand_regs_read(self, instruction: CsInsn) -> Set[Register]:
        if any(not hasattr(operand, "access") for operand in instruction.operands):
            return set()

        registers = set()
        for operand in instruction.operands:
            if operand.type == CS_OP_MEM:
                registers.update(self._operand_registers(instruction, operand))
                continue
            if operand.type != CS_OP_REG or not (operand.access & CS_AC_READ):
                continue
            reg = self._reg_name_to_register(instruction.reg_name(operand.reg))
            if reg is not None:
                registers.add(reg)
        return registers

    def _register_access_size(self, reg: Register, reg_name: str) -> int:
        for size, name in reg.sizes.items():
            if name != reg_name:
                continue
            try:
                return int(str(size).rstrip("lh"))
            except ValueError:
                break

        try:
            return int(str(reg.default_size).rstrip("lh"))
        except ValueError:
            return 0

    def _instruction_regs_read_fallback(self, instruction: CsInsn) -> Set[Register]:
        return self.semantics.instruction_regs_read_fallback(instruction)

    def _instruction_regs_write_fallback(self, instruction: CsInsn) -> Set[Register]:
        return self.semantics.instruction_regs_write_fallback(instruction)

    def _operand_registers(self, instruction: CsInsn, operand, *, include_memory_base: bool = True) -> Set[Register]:
        registers = set()
        reg_id = getattr(operand, "reg", 0) if operand.type == CS_OP_REG else 0
        if reg_id:
            reg = self._reg_name_to_register(instruction.reg_name(reg_id))
            if reg is not None:
                registers.add(reg)

        if include_memory_base and operand.type == CS_OP_MEM:
            mem = getattr(operand, "mem", None)
            base_id = getattr(mem, "base", 0)
            if base_id:
                reg = self._reg_name_to_register(instruction.reg_name(base_id))
                if reg is not None:
                    registers.add(reg)
            index_id = getattr(mem, "index", 0)
            if index_id:
                reg = self._reg_name_to_register(instruction.reg_name(index_id))
                if reg is not None:
                    registers.add(reg)

        return registers

    def _get_in_regs(self, block: gtirb.CodeBlock, instructions: List[CsInsn], instruction_idx: int) -> Set[Register]:
        if not instructions:
            return set(self.abi.all_registers())

        if block.uuid not in self.in_regs:
            self.in_regs[block.uuid] = [set() for _ in instructions]
        return self.in_regs[block.uuid][instruction_idx]

    def _set_in_regs(self, block: gtirb.CodeBlock, instructions: List[CsInsn], instruction_idx: int,
                     in_regs: Set[Register]) -> bool:
        old_in_regs = self._get_in_regs(block, instructions, instruction_idx)
        self.in_regs[block.uuid][instruction_idx] = in_regs

        return old_in_regs != in_regs
