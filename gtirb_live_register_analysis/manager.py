import gtirb
import uuid
import copy
import itertools

from gtirb_functions import Function
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting.assembly import Register
from gtirb_rewriting.patch import Constraints, InsertionContext
from typing import Optional, Dict, List, Set

from .utils import CachedGtirbInstructionDecoder
from .analysis import LiveRegisterAnalyzer
from .abi import AnalysisAwareABI, _X86_64_ELF


class NotEnoughFreeRegistersException(Exception):
    pass


class LiveRegisterManager:
    module: gtirb.Module
    abi: AnalysisAwareABI
    analyzer: LiveRegisterAnalyzer

    #  usage: result_cache[function_uuid][block_uuid][instruction_idx]
    result_cache: Dict[uuid.UUID, Dict[uuid.UUID, List[Set[Register]]]] = dict()

    def __init__(self, module: gtirb.Module, abi: AnalysisAwareABI = _X86_64_ELF(),
                 decoder: Optional[GtirbInstructionDecoder] = None):
        self.module = module
        self.abi = abi

        if decoder is None:
            decoder = CachedGtirbInstructionDecoder(module.isa)
        self.analyzer = LiveRegisterAnalyzer(self.abi, decoder)

    def analyze(self, function: Function):
        if function.uuid in self.result_cache:
            return

        self.result_cache[function.uuid] = self.analyzer.analyze(function)

    def live_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int) -> Set[Register]:
        assert function.uuid in self.result_cache, "Live registers of function have not been analyzed"

        if block.uuid not in self.result_cache[function.uuid]:
            # If a block is not analyzed for some reason, we conservatively disable live register analysis
            return set(self.abi.all_registers())

        return self.result_cache[function.uuid][block.uuid][instruction_idx]

    def add_live_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int,
                           registers: Set[Register]):
        self.live_registers(function, block, instruction_idx).update(registers)

    def free_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int) -> Set[Register]:
        return set(self.abi._scratch_registers()).difference(self.live_registers(function, block, instruction_idx))

    def allocate_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int,
                           allow_fallback: bool = True):
        """
        Resolves scratch registers for a patch function in the given context.
        :param allow_fallback: allows falling back to push original register contents to stack when there
                               are not enough free registers. If false, an exception will be raised.
        """

        def patch_func_decorator(f):
            assert hasattr(f, "constraints"), "Constraints of function patch are not set"
            constraints: Constraints = copy.deepcopy(f.constraints)
            free_registers = self.free_registers(function, block, instruction_idx)

            assignable_registers_count = min(len(free_registers), constraints.scratch_registers)
            assigned_registers = list(itertools.islice(free_registers, assignable_registers_count))

            # Update the constraint so the remaining scratch registers will fall back to the rewriter
            constraints.scratch_registers -= assignable_registers_count
            constraints.reads_registers.update({x.name for x in assigned_registers})
            if constraints.scratch_registers > 0 and not allow_fallback:
                raise NotEnoughFreeRegistersException()

            if constraints.clobbers_flags and \
                    self.abi.flag_register() not in self.live_registers(function, block, instruction_idx):
                constraints.clobbers_flags = False

            def func_wrapper(ctx: InsertionContext):
                ctx.scratch_registers += assigned_registers
                return f(ctx)

            func_wrapper.constraints = constraints
            return func_wrapper

        return patch_func_decorator
