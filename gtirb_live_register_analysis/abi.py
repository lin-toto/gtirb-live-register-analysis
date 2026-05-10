import gtirb

from .abis import (
    AnalysisAwareABI,
    _AARCH64_ELF,
    _ARM64_ELF,
    _ARM64_ELF_BASE,
    _RISCV64_ELF,
    _X86_64_ELF,
)
from .module_info import module_isa_name


def abi_for_module(module: gtirb.Module) -> AnalysisAwareABI:
    if module.file_format != gtirb.Module.FileFormat.ELF:
        raise NotImplementedError(f"Unsupported file format: {module.file_format}")

    isa_name = module_isa_name(module)
    if isa_name == "X64":
        return _X86_64_ELF()

    if isa_name in ("ARM64", "AARCH64"):
        if _ARM64_ELF_BASE is None:
            raise ImportError("gtirb-rewriting does not provide an ARM64 ELF ABI")
        return _ARM64_ELF()

    if isa_name == "RISCV64":
        return _RISCV64_ELF()
    if isa_name in ("RISCV32", "RISCV"):
        raise NotImplementedError(
            "gtirb-live-register-analysis only supports RV64 RISC-V modules; "
            "RV32 and generic RISCV modules are not supported"
        )

    raise NotImplementedError(
        f"Unsupported ISA/file format pair: {isa_name}/{module.file_format}"
    )


__all__ = [
    "AnalysisAwareABI",
    "abi_for_module",
    "_AARCH64_ELF",
    "_ARM64_ELF",
    "_RISCV64_ELF",
    "_X86_64_ELF",
]
