import archinfo
import angr
import time
import autocoop.esl_lib.lib_utils.angr_extensions as angr_extensions

def ensure_args(self, state, args):
    """
    Adds constraints to make sure that the values for the arguments have been loaded to the correct registers

    :param state: state of the app after the gadget has been run. Constraints will be added to this object.
    :param list[Variable] args: arguments that have to be loaded

    .. todo::
      Different strategies depending on operating system.

    """
    arg_names = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    if len(args) > 6:
        print "Too many args"
        print args
        raise NotImplementedError()
    for i, arg in enumerate(args):
        reg = state.regs.__getattr__(arg_names[i])
        if arg.is_ptr:
            if type(arg.value) == int:
                state.solver.add(state.memory.load(reg, 8) == arg.value)
            else:
                try:
                    if len(state.solver.eval_atleast(reg, 2)) > 1:
                        self.pointers.update({self.self_pointer+self.object_size-len(arg.value): bytes(arg.value)})
                        state.memory.read_strategies.insert(0, angr_extensions.ResolveSingleAddress(self.self_pointer+self.object_size-len(arg.value)))
                    res = state.solver.add(state.memory.load(reg, len(arg.value)) == bytes(arg.value))
                except Exception as e:
                    state.solver.add(1==2)
        elif not arg.value:
            pass
        else:
            state.solver.add(reg == arg.value)

    # arg = args[0]
    # if arg.is_ptr:
    #     if type(arg.value) == int:
    #         state.solver.add(state.memory.load(state.regs.rdi, 8) == arg.value)
    #     else:
    #         try:
    #             if len(state.solver.eval_atleast(state.regs.rdi, 2)) > 1:
    #                 self.pointers.update({self.self_pointer+self.object_size-len(arg.value): bytes(arg.value)})
    #                 state.memory.read_strategies.insert(0, angr_extensions.ResolveSingleAddress(self.self_pointer+self.object_size-len(arg.value)))
    #             res = state.solver.add(state.memory.load(state.regs.rdi, len(arg.value)) == bytes(arg.value))
    #             if not res:
    #                 state.solver.add(1==2)
    #         except Exception as e:
    #             state.solver.add(1==2)
    # else:
    #     state.solver.add(state.regs.rdi == arg.value)


def ensure_vptr(state, vtable_addr, self_ptr):
    """
    Adds constraints to check that the vptr points to the correct vtable

    :param state: state of the app after the gadget has been run. Constaints will be added to this object.
    :param int vtable_addr: address of the vtable
    :param int self_ptr: address of the start of the object
    :return:
    """
    state.solver.add(state.memory.load(self_ptr, 8, endness=archinfo.Endness.LE) == vtable_addr)


def int_to_bytes(number, n_bytes):
    """
    Makes a bytestring out of an integer

    :param int number: integer to be transformed
    :param int n_bytes: expected number of bytes, to make sure leading zeroes are generated correctly
    :return: bytestring of the integer
    :rtype: str
    """
    as_hex = "{value:0>{align}x}".format(value=number, align=n_bytes * 2)
    n = 2
    pairs = [as_hex[i:i+n] for i in range(0, len(as_hex), n)]
    bytearray = map(lambda x: chr(int(x, 16)), pairs)
    return "".join(bytearray)


class CheckUniquenessAndFind(angr.exploration_techniques.Explorer):
    """
    Exploration technique for the angr simulation manager that searches for some addresses, avoiding some other
    addresses, without visiting the same block twice. The latter condition is to avoid loops.

    :param list[int] find: find these addresses
    :param list[int] avoid: avoid these addresses
    """
    def __init__(self, *args, **kwargs):
        super(CheckUniquenessAndFind, self).__init__(*args, **kwargs)
        self.unique_blocks = set()
        self.start = time.time()

    def filter(self, simgr, state, *args):
        if len(self.unique_blocks) > 5:
            return "too_many_blocks"
        res = super(CheckUniquenessAndFind, self).filter(simgr, state, *args)
        if res:
            return res
        if time.time() - self.start > 10:
            return "timeout"
        ip = state.solver.eval(state.regs.rip)
        if ip in self.unique_blocks:
            return "not_unique_block"
        self.unique_blocks.add(ip)
        return None

class CheckUniquenessAndReturn(angr.ExplorationTechnique):
    """
    Exploration technique for angr simulation manager that searches for a return from the starting function, without
    visiting the same block twice.
    """
    def __init__(self):
        super(CheckUniquenessAndReturn, self).__init__()
        self.unique_blocks = set()
        self.gadget_limits = None

    def filter(self, simgr, state, *args):
        ip = state.solver.eval(state.regs.rip)
        if not self.gadget_limits:
            symbol = state.project.loader.find_symbol(ip)
            self.gadget_limits = (symbol.rebased_addr, symbol.rebased_addr + symbol.size)
        # if ip == 0x7ffff7ff3260:
        #     pass
        # try:
        #     if ip != 0 and ip != 0xdeadbeef:
        #         self.project.factory.block(ip).pp()
        # except: pass
        if ip in self.unique_blocks:
            return "not_unique_block"
        if state.jumpkind == "Ijk_Call" and (ip < self.gadget_limits[0] or ip > self.gadget_limits[1]):
            return "call"
        if ip == 0x0:
            if state.jumpkind != "Ijk_Ret" and state.jumpkind:
                return "jump_to_zero"
        if ip == 0xdeadbeef:
            if state.jumpkind == "Ijk_Ret":
                return "state_return"
        self.unique_blocks.add(ip)
        return None

def resolve_reg(register):
    """
    Changes a platform independant register id (_r1, _r2, ...) into a platform specific one (rdi, rsi, ...)

    :param str register: register to translate
    :return: platform specific register id
    :rtype: str

    .. todo::
      Support for platforms other than Linux 64 bit

    """
    param_regs_linux = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    register_number = int(register[-1])
    return param_regs_linux[register_number]

def alternatives(register):
    """
    Gets different length names for the same register (rdi, esi, si)

    :param register:
    :return:
    """
    alternatives = [
        {"rdi", "edi", "di"},
        {"rsi", "esi", "si"},
        {"rdx", "edx", "dx"},
        {"rcx", "ecx", "cx"},
        {"r8", "r8d", "r8w"},
        {"r9", "r9d", "r9w"}
    ]
    for alternative in alternatives:
        if register in alternative:
            return alternative
    return {register}


def ensure_postconditions(self, state, gadget):
    """
    Ensures that all asserts following the gadget asserts are true.

    :param state: state to add conditions to
    :param gadget: gadget to ensure postconditions of
    """
    for regname, cmpop, value in gadget.postconditions:
        is_ptr = False
        if not type(value) == int:
            value, is_ptr = get_from_assignments(gadget.assignments, value)
        reg = state.regs.__getattr__(resolve_reg(regname))
        if not is_ptr:
            cmpops = {
                "==": reg.__eq__,
                ">": reg.__gt__,
                "<": reg.__lt__
            }
            state.solver.add(cmpops[cmpop](value))
        else:
            if type(value) == int:
                target_mem = state.memory.load(reg, 8)
                cmpops = {
                    "==": target_mem.__eq__,
                    ">": target_mem.__gt__,
                    "<": target_mem.__lt__
                }
                state.solver.add(cmpops[cmpop](value))
            else:
                if len(state.solver.eval_upto(reg, 2)) > 1:
                    self.pointers.update({self.self_pointer+self.object_size-len(value): bytes(value)})
                    state.memory.read_strategies.insert(0, angr_extensions.ResolveSingleAddress(self.self_pointer+self.object_size-len(value)))
                target_mem = state.memory.load(reg, len(value))
                cmpops = {
                    "==": target_mem.__eq__,
                    ">": target_mem.__gt__,
                    "<": target_mem.__lt__
                }
                state.solver.add(cmpops[cmpop](value))
                if self.registers[resolve_reg(regname)] != None and len(state.solver.eval_upto(self.registers[resolve_reg(regname)], 2)) < 2:
                    state.solver.add(1==2)
                    return

def get_from_assignments(assignments, name):
    for variable in assignments[::-1]:
        if variable.name == name:
            return variable.value, variable.is_ptr
    raise Exception("Unknown variable or register: {}".format(name))

def get_assigned_registers(gadget):
    res = set()
    for assignment in gadget.assignments[::-1]:
        if assignment.name.startswith("_r") and assignment.value:
            res.add(resolve_reg(assignment.name))
    return res

def get_condition_registers(gadget):
    res = set()
    for condition in gadget.postconditions:
        if condition[0].startswith("_r"):
            res.add(resolve_reg(condition[0]))
    return res

def ensure_preconditions(state, gadget):
    """
    Ensures that all preconditions (register and memory assignments) are met

    :param state: state to add conditions to
    :param gadget: gadget to ensure preconditions of
    """
    for assignment in gadget.assignments[::-1]:
        if assignment.name.startswith("_r") and assignment.value:
            state.regs.__setattr__(resolve_reg(assignment.name), assignment.value)
