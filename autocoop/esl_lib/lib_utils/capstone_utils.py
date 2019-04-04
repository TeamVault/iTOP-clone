import capstone.arm64 as arm64

def insns_generator(insns):
    """
    Iterates through the list of instructions

    :param insns: list of instructions to iterate through
    :yields: instructions
    """
    for insn in insns:
        yield insn

def find_reg_source(insn, reg):
    """
    Finds if the register is assigned in the instruction, and if so, returns the source

    :param insn: instruction to search
    :param reg: register to look for
    :return: operand.mem.base, operand.mem.disp, operand.mem.index, operand.mem.scale
    """
    if not (insn.mnemonic.startswith("mov") and insn.operands[0].reg == reg):
        return reg, None, None, None
    operand = insn.operands[1]
    if operand.type == arm64.ARM64_OP_MEM:
        return operand.mem.base, operand.mem.disp, operand.mem.index, operand.mem.scale
    elif operand.type == arm64.ARM64_OP_REG:
        return operand.reg, None, None, None

def get_function_capstone(app, gadget):
    """
    Get the disassembly of a function in capstone format

    :param app: Angr project
    :param gadget: Symbol to disassemble
    :return: List of capstone assembly instructions
    :rtype: list
    """
    if gadget.size > 1000:
        return []
    insns = []
    addr = gadget.rebased_addr
    while addr < gadget.rebased_addr + gadget.size:
        block = app.factory.block(addr)
        if block.size == 0:
            return []
        addr += block.size
        insns.extend(block.capstone.insns)
    return insns


def get_function_capstone_print(app, gadget):
    """
    Get the disassembly of a function in capstone format and prints the disassembly

    :param app: Angr project
    :param gadget: Symbol to disassemble
    :return: List of capstone assembly instructions
    :rtype: list
    """
    insns = []
    addr = gadget.rebased_addr
    while addr < gadget.rebased_addr + gadget.size:
        block = app.factory.block(addr)
        block.pp()
        addr += block.size
        insns.extend(block.capstone.insns)
    return insns

def find_index_for_addr(insns, target):
    """
    Gets the index of an address in an instruction list

    :param list insns: Capstone instruction list
    :param int target: Address to look for
    :return: Index of address in list
    :rtype: int
    """
    for index, insn in enumerate(insns):
        if insn.insn.address == target:
            return index
    return None

