import gtirb
import uuid
import copy
import warnings

from gtirb_functions import Function
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting.assembly import Register
from gtirb_rewriting.patch import Constraints, InsertionContext
from typing import Optional, Dict, List, Mapping, Set, Tuple

from .utils import CachedGtirbInstructionDecoder
from .analysis import LiveRegisterAnalyzer
from .abi import AnalysisAwareABI, abi_for_module


LIVE_REGISTER_NAMES_AUXDATA = "liveRegisterNames"
LIVE_REGISTER_SETS_AUXDATA = "liveRegisterSets"
LIVE_REGISTER_NAMES_TYPE = "sequence<string>"
LIVE_REGISTER_SETS_TYPE = "mapping<Offset,uint64_t>"


class NotEnoughFreeRegistersException(Exception):
    pass


class LiveRegisterManager:
    module: gtirb.Module
    abi: AnalysisAwareABI
    analyzer: LiveRegisterAnalyzer

    #  usage: result_cache[function_uuid][block_uuid][instruction_idx]
    result_cache: Dict[uuid.UUID, Dict[uuid.UUID, List[Set[Register]]]]

    def __init__(self, module: gtirb.Module, abi: Optional[AnalysisAwareABI] = None,
                 decoder: Optional[GtirbInstructionDecoder] = None, *,
                 analysis_scope: str = "function"):
        self.module = module
        self.abi = abi if abi is not None else abi_for_module(module)
        self.result_cache = dict()

        if decoder is None:
            decoder = CachedGtirbInstructionDecoder(module.isa)
        self.analyzer = LiveRegisterAnalyzer(self.abi, decoder, analysis_scope=analysis_scope)
        self._analysis_scope = analysis_scope
        self._fallback_reason = None
        self.refresh()

    def refresh(self, *, preserve_liveness: bool = False):
        """Reload migrated metadata after an IR edit and discard per-round state.

        Set preserve_liveness only for edits that preserve the original
        register dependencies and control-flow meaning, with migrated offsets.
        Otherwise invalidate the module: changed uses can affect predecessors
        and callers, not only the instruction whose bytes were replaced.
        New or replaced instructions without a mask are treated as all-live;
        invalidation does not trigger Python analysis.
        """
        if not preserve_liveness and getattr(self, "_metadata_sets", None) is not None:
            sets_aux = self.module.aux_data.get(LIVE_REGISTER_SETS_AUXDATA)
            if (sets_aux is not None and sets_aux.type_name == LIVE_REGISTER_SETS_TYPE and
                    isinstance(sets_aux.data, Mapping) and sets_aux.data):
                count = len(sets_aux.data)
                sets_aux.data = {}
                warnings.warn(
                    f"module {self.module.name!r}: invalidating {count} live-register masks "
                    "after an unspecified edit; all instructions remain all-live. "
                    "Use preserve_liveness=True only for dependency-preserving edits",
                    RuntimeWarning,
                    stacklevel=2,
                )
        self.result_cache.clear()
        if isinstance(self.analyzer.decoder, CachedGtirbInstructionDecoder):
            self.analyzer.decoder.cache.clear()
        self._metadata_registers, self._metadata_sets = self._load_metadata()
        self.analysis_source = "ddisasm" if self._metadata_sets is not None else "python"

    def _load_metadata(self) -> Tuple[Optional[List[Register]], Optional[Mapping[gtirb.Offset, int]]]:
        names_aux = self.module.aux_data.get(LIVE_REGISTER_NAMES_AUXDATA)
        sets_aux = self.module.aux_data.get(LIVE_REGISTER_SETS_AUXDATA)
        try:
            if names_aux is None or sets_aux is None:
                raise ValueError("both live-register auxdata tables are required")
            if names_aux.type_name != LIVE_REGISTER_NAMES_TYPE:
                raise ValueError(f"unexpected {LIVE_REGISTER_NAMES_AUXDATA} type")
            if sets_aux.type_name != LIVE_REGISTER_SETS_TYPE:
                raise ValueError(f"unexpected {LIVE_REGISTER_SETS_AUXDATA} type")

            names = list(names_aux.data)
            if not names or len(names) > 64 or any(
                    not isinstance(name, str) or not name for name in names):
                raise ValueError("register-name table must contain 1-64 non-empty names")

            registers = [self.abi.get_register(name) for name in names]
            if len(set(registers)) != len(registers):
                raise ValueError("register-name table contains aliases of the same register")
            if not set(self.abi._scratch_registers()).issubset(registers):
                raise ValueError("register-name table omits allocatable scratch registers")
            flag_register = self.abi.flag_register()
            if flag_register is not None and flag_register not in registers:
                raise ValueError("register-name table omits the condition flags")

            valid_bits = (1 << len(registers)) - 1
            register_sets = sets_aux.data
            if not isinstance(register_sets, Mapping):
                raise ValueError("live-register data is not a mapping")
        except (KeyError, TypeError, ValueError) as error:
            reason = str(error)
            if reason != self._fallback_reason:
                warnings.warn(
                    f"module {self.module.name!r}: falling back to Python "
                    f"{self._analysis_scope}-scope live-register analysis: {reason}",
                    RuntimeWarning,
                    stacklevel=3,
                )
            self._fallback_reason = reason
            return None, None

        invalid_entries = set()
        for offset, mask in register_sets.items():
            if (not isinstance(offset, gtirb.Offset) or
                    not isinstance(offset.element_id, gtirb.CodeBlock) or
                    offset.element_id.module is not self.module or
                    not isinstance(offset.displacement, int) or
                    not 0 <= offset.displacement < offset.element_id.size or
                    not isinstance(mask, int) or mask < 0 or mask & ~valid_bits):
                invalid_entries.add(offset)
        if invalid_entries:
            # Missing masks are all-live. Remove bad entries from the AuxData
            # too, so subsequent rewriter offset hooks only see valid keys.
            register_sets = {
                offset: mask for offset, mask in register_sets.items()
                if offset not in invalid_entries
            }
            sets_aux.data = register_sets
            warnings.warn(
                f"module {self.module.name!r}: discarded {len(invalid_entries)} "
                "invalid live-register entries; retaining DDisasm metadata "
                "with missing instructions treated as all-live",
                RuntimeWarning,
                stacklevel=3,
            )

        self._fallback_reason = None
        return registers, register_sets

    def analyze(self, function: Function):
        if function.uuid in self.result_cache:
            return

        if self._metadata_sets is None:
            self.result_cache[function.uuid] = self.analyzer.analyze(function)
            return

        all_registers = set(self.abi.all_registers())
        function_registers = {}
        for block in function.get_all_blocks():
            block_registers = []
            for instruction in self.analyzer.decoder.get_instructions(block):
                if block.address is None:
                    block_registers.append(set(all_registers))
                    continue

                offset = gtirb.Offset(block, instruction.address - block.address)
                mask = self._metadata_sets.get(offset)
                if mask is None:
                    block_registers.append(set(all_registers))
                    continue

                block_registers.append({
                    register
                    for index, register in enumerate(self._metadata_registers)
                    if mask & (1 << index)
                })
            function_registers[block.uuid] = block_registers

        self.result_cache[function.uuid] = function_registers

    def live_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int) -> Set[Register]:
        assert function.uuid in self.result_cache, "Live registers of function have not been analyzed"

        if block.uuid not in self.result_cache[function.uuid]:
            # If a block is not analyzed for some reason, we conservatively disable live register analysis
            return set(self.abi.all_registers())

        block_registers = self.result_cache[function.uuid][block.uuid]
        if instruction_idx < 0 or instruction_idx >= len(block_registers):
            return set(self.abi.all_registers())

        return block_registers[instruction_idx]

    def add_live_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int,
                           registers: Set[Register]):
        self.live_registers(function, block, instruction_idx).update(registers)

    def free_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int) -> Set[Register]:
        return set(self.abi._scratch_registers()).difference(self.live_registers(function, block, instruction_idx))

    def _free_registers_ordered(self, function: Function, block: gtirb.CodeBlock,
                                instruction_idx: int) -> List[Register]:
        live_registers = self.live_registers(function, block, instruction_idx)
        return [reg for reg in self.abi._scratch_registers()
                if reg not in live_registers]

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
            free_registers = self._free_registers_ordered(function, block, instruction_idx)

            assignable_registers_count = min(len(free_registers), constraints.scratch_registers)
            assigned_registers = free_registers[:assignable_registers_count]

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
