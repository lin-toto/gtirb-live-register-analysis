class X64:
    ARGUMENT_REGISTERS = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
    CALLEE_PRESERVED_REGISTERS = set()#{"rbx", "rsp", "rbp", "r12", "r13", "r14", "r15"}
    RETURN_REGISTERS = set()#{"rax", "rdx"}

    FULL_REGISTERS_MAP = {'ah': 'rax', 'al': 'rax', 'ax': 'rax', 'eax': 'rax', 'rax': 'rax',
                          'bh': 'rbx', 'bl': 'rbx', 'bx': 'rbx', 'ebx': 'rbx', 'rbx': 'rbx',
                          'ch': 'rcx', 'cl': 'rcx', 'cx': 'rcx', 'ecx': 'rcx', 'rcx': 'rcx',
                          'dh': 'rdx', 'dl': 'rdx', 'dx': 'rdx', 'edx': 'rdx', 'rdx': 'rdx',
                          'bp': 'rbp', 'bpl': 'rbp', 'ebp': 'rbp', 'rbp': 'rbp',
                          'sp': 'rsp', 'spl': 'rsp', 'esp': 'rbp', 'rsp': 'rbp',
                          'di': 'rdi', 'dih': 'rdi', 'dil': 'rdi', 'edi': 'rdi', 'rdi': 'rdi',
                          'si': 'rsi', 'sih': 'rsi', 'sil': 'rsi', 'esi': 'rsi', 'rsi': 'rsi',
                          'r8': 'r8', 'r8b': 'r8', 'r8d': 'r8', 'r8w': 'r8',
                          'r9': 'r9', 'r9b': 'r9', 'r9d': 'r9', 'r9w': 'r9',
                          'r10': 'r10', 'r10b': 'r10', 'r10d': 'r10', 'r10w': 'r10',
                          'r11': 'r11', 'r11b': 'r11', 'r11d': 'r11', 'r11w': 'r11',
                          'r12': 'r12', 'r12b': 'r12', 'r12d': 'r12', 'r12w': 'r12',
                          'r13': 'r13', 'r13b': 'r13', 'r13d': 'r13', 'r13w': 'r13',
                          'r14': 'r14', 'r14b': 'r14', 'r14d': 'r14', 'r14w': 'r14',
                          'r15': 'r15', 'r15b': 'r15', 'r15d': 'r15', 'r15w': 'r15',
                          'rflags': 'rflags'}
