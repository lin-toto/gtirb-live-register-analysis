import capstone
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone import CsInsn
from typing import Dict, Iterator

from .module_info import module_is_riscv64, module_is_unsupported_riscv

# RV64GC. Capstone 6 decodes the A, F and D extensions only when their mode flags are set (Capstone 5
# always decoded them and has no such flags). Teapot's decoders (teapot.arch.decoders) use the same
# configuration, so both see the same instructions.
RISCV64_MODE = (capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC |
                getattr(capstone, "CS_MODE_RISCV_A", 0) | getattr(capstone, "CS_MODE_RISCV_FD", 0))


def configure_riscv64(decoder: capstone.Cs) -> capstone.Cs:
    """Real, uncompressed instructions with complete details under Capstone 6.

    Capstone 6's alias details drop the link register of `jal`, `jalr` and `ret` from the operands,
    the register accesses and the call group; the uncompressed real form lists every operand. A
    compressed instruction keeps its 2-byte size. Capstone 5 has neither option and is left as is.
    """
    syntax = getattr(capstone, "CS_OPT_SYNTAX_UNCOMPRESSED_REAL", None)
    if syntax is None:
        decoder.detail = True
        return decoder
    decoder.syntax = syntax
    decoder.option(capstone.CS_OPT_DETAIL, capstone.CS_OPT_ON | capstone.CS_OPT_DETAIL_UNCOMPRESSED_REAL)
    return decoder


class CachedGtirbInstructionDecoder(GtirbInstructionDecoder):
    cache: dict = {}

    def get_instructions(self, block: gtirb.CodeBlock) -> Iterator[CsInsn]:
        if block.uuid in self.cache:
            return iter(self.cache[block.uuid])

        if module_is_unsupported_riscv(block.module):
            raise NotImplementedError("RV32 and generic RISC-V decoding are not supported")
        if block.size == 0:
            result = []
        elif module_is_riscv64(block.module):
            result = list(self._get_riscv64_decoder(block).disasm(block.contents, block.address or block.offset))
        else:
            result = list(super().get_instructions(block))
        self.cache[block.uuid] = result

        return iter(result)

    def _get_riscv64_decoder(self, block: gtirb.CodeBlock) -> capstone.Cs:
        if not hasattr(self, "_riscv64_decoders"):
            self._riscv64_decoders: Dict[int, capstone.Cs] = {}

        endian = (capstone.CS_MODE_BIG_ENDIAN if block.module and
                  block.module.byte_order == gtirb.Module.ByteOrder.Big else capstone.CS_MODE_LITTLE_ENDIAN)
        mode = RISCV64_MODE | endian
        if mode not in self._riscv64_decoders:
            self._riscv64_decoders[mode] = configure_riscv64(capstone.Cs(capstone.CS_ARCH_RISCV, mode))
        return self._riscv64_decoders[mode]
