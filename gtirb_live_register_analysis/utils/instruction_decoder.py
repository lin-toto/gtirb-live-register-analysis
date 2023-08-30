import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from typing import Iterator


class CachedGtirbInstructionDecoder(GtirbInstructionDecoder):
    cache: dict = {}

    def get_instructions(self, block: gtirb.CodeBlock) -> Iterator[CsInsn]:
        if block.uuid in self.cache:
            return iter(self.cache[block.uuid])

        result = list(super().get_instructions(block))
        self.cache[block.uuid] = result

        return iter(result)
