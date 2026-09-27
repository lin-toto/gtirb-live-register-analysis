import capstone
import gtirb
import importlib
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone import CsInsn
from typing import Dict, Iterator

from .module_info import module_is_riscv64, module_is_unsupported_riscv


def _riscv_decoder_module():
    try:
        return importlib.import_module("gtirb_rewriting.decoder")
    except ModuleNotFoundError as error:
        if error.name != "gtirb_rewriting.decoder":
            raise
        raise RuntimeError(
            "RV64 decoding requires the lin-toto/gtirb-rewriting fork with "
            "gtirb_rewriting.decoder; install the revision pinned by Teapot"
        ) from error


def configure_riscv64(decoder: capstone.Cs) -> capstone.Cs:
    return _riscv_decoder_module().configure_riscv64(decoder)


def __getattr__(name):
    # Preserve the old configuration export without a second definition or
    # making users of only x64/AArch64 depend on the RISC-V fork API.
    if name == "RISCV64_MODE":
        return _riscv_decoder_module().RISCV64_MODE
    raise AttributeError(name)

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
        if endian not in self._riscv64_decoders:
            self._riscv64_decoders[endian] = _riscv_decoder_module().riscv64_decoder(endian)
        return self._riscv64_decoders[endian]
