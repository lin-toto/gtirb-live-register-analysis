import gtirb


def module_isa_name(module: gtirb.Module) -> str:
    if module is None:
        return ""

    isa_name = module.isa.name
    if isa_name == "ValidButUnsupported" and "archInfo" in module.aux_data:
        arch_info = module.aux_data["archInfo"].data
        if isinstance(arch_info, dict) and "ISA" in arch_info:
            isa_name = arch_info["ISA"]
    return str(isa_name).upper()


def module_is_riscv64(module: gtirb.Module) -> bool:
    return module_isa_name(module) == "RISCV64"


def module_is_unsupported_riscv(module: gtirb.Module) -> bool:
    return module_isa_name(module) in ("RISCV32", "RISCV")
