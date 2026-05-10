import capstone
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone import CsInsn
from typing import Dict, Iterator

from .module_info import module_is_riscv64, module_is_unsupported_riscv


class CachedGtirbInstructionDecoder(GtirbInstructionDecoder):
    cache: dict = {}

    def get_instructions(self, block: gtirb.CodeBlock) -> Iterator[CsInsn]:
        if block.uuid in self.cache:
            return iter(self.cache[block.uuid])

        if module_is_unsupported_riscv(block.module):
            raise NotImplementedError("RV32 and generic RISC-V decoding are not supported")
        if module_is_riscv64(block.module):
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
        mode = capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC | endian
        if mode not in self._riscv64_decoders:
            self._riscv64_decoders[mode] = capstone.Cs(capstone.CS_ARCH_RISCV, mode)
            self._riscv64_decoders[mode].detail = True
        return self._riscv64_decoders[mode]
