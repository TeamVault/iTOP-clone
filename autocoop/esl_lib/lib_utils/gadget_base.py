from __builtin__ import False

from capstone import arm64

import autocoop.esl_lib.lib_utils.candidate_finder as candidate_finder
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import logging
import autocoop.builder.builder as builder
import angr
import archinfo
import tqdm
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
import gc
import signal

class Gadget(object):
    """
    Base represtation of a gadget.

    :param app: Parent angr project
    :param Config config: Config of app
    :param autocoop.esl.parser.Gadget gadget_def: IR of gadget
    :param list calltarget_list: List of valid calltargets
    """
    name = "DEFAULT"
    sem_filter = {}
    sem_blacklist = {"call": ("any",)}
    sem_filter_max_size = 32

    def __init__(self, app, config, gadget_def, calltarget_list=list(), calltarget_id=0):
        self.app = app
        self.config = config
        self.gadget_def = gadget_def
        self.self_pointer = config.base_buf
        self.symbolic_object = None
        self.candidates = calltarget_list #[458:]
        self.registers = {"rax": None, "rbx": None, "rcx": None, "rdx": None, "rsi": None,
                          "rdi": None, "r8": None, "r9": None, "r10": None, "r11": None, "r12": None, "r13": None,
                          "r14": None, "r15": None}
        self.object_size = 0x60
        self.pointers = {}
        self.calltarget_id = calltarget_id

    def get_candidates(self):
        """
        Generates a list of calltargets
        """
        self.candidates = candidate_finder.get_candidate_gadgets_from_csv(self.app, self.config.other_args["gadget_csv"])

    def setup_state(self, gadget_symbol, vtable_addr):
        """
        Sets up the angr state

        :param gadget_symbol: Symbol of gadget
        :param vtable_addr: Vtable address of gadget
        :return: Angr state
        """
        state = self.app.factory.call_state(gadget_symbol.rebased_addr, self.self_pointer,
                                       add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.LAZY_SOLVES}, ret_addr=0xdeadbeef)
        self.setup_symbolic_registers(state)
        self.ensure_preconditions(state, self.gadget_def)
        self.symbolic_object = state.solver.BVS("symbolic_object", self.object_size * 8)

        if self.app.kb.virtual_dispatch:
            state.memory.store(self.self_pointer, vtable_addr, endness=archinfo.Endness.LE)
            self.symbolic_object_offset = 8
        else:
            self.symbolic_object_offset = 0
        state.memory.store(self.self_pointer+self.symbolic_object_offset, self.symbolic_object)
        if vtable_addr != 1:
            state.memory.store(vtable_addr, self.app.kb.entry_state.memory.load(vtable_addr, 64))
        if not self.app.kb.virtual_dispatch:
            state.solver.add(state.memory.load(self.self_pointer+self.config.vptr_offset*8, 8, endness=archinfo.Endness.LE) == gadget_symbol.rebased_addr)
        return state

    def ensure_preconditions(self, state, gadget_def):
        solver_utils.ensure_preconditions(state, gadget_def)

    def setup_symbolic_registers(self, state):
        assigned = solver_utils.get_assigned_registers(self.gadget_def)
        for key in self.registers:
            if key not in assigned and key != "rdi":
                self.registers[key] = state.solver.BVS(key, 64)
                state.solver.add(state.regs.__getattr__(key) == self.registers[key])

    def simulate(self, state):
        """
        Simulates a state until the exit condition is met

        :param state: State to simulate
        :return: List of valid resulting states
        :rtype: list
        """
        def timeout_handler(signum, frame):
            raise Exception("timeout")
        simgr = self.app.factory.simgr(state)
        simgr.use_technique(solver_utils.CheckUniquenessAndReturn())
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(10)
        try:
            simgr.run()
            signal.alarm(0)
        except Exception as e:
            logging.getLogger("autocoop.esl_lib.gadgets").info(
                "[*] Simulation taking too long, killing.")
        finally:
            signal.alarm(0)
        if "state_return" in simgr.stashes:
            res =  simgr.state_return
            del simgr
            return res
        return []

    def add_constraints(self, state):
        """
        Adds constraints to state

        :param state: State to modify
        """
        pass

    def add_postconditions(self, state, vtable_addr, gadget):
        """
        Adds postconditions to state

        :param state: State to modify
        :param int vtable_addr: Vtable addr of gadget
        :param gadget: IR of gadget
        """
        solver_utils.ensure_postconditions(self, state, self.gadget_def)

    def generate_object(self, state, vtable_addr, gadget):
        """
        Generates the object to add to the builder

        :param state: State to get the object from
        :param vtable_addr: Vtable addr of gadget
        :param gadget: IR of gadget
        :return: Gadget address and builder object
        """
        if state.solver.satisfiable():
            object_data = state.solver.eval(self.symbolic_object)
        else:
            return None
        state.solver.add(self.symbolic_object == object_data)
        for reg, bv in self.registers.items():
            if bv != None:
                if len(state.solver.eval_upto(bv, 2)) < 2:
                    logging.getLogger("autocoop.esl_lib.gadgets").info("[*] Gadget {} depends on register initialization".format(self.name))
                    return None
        if self.app.kb.virtual_dispatch:
            if vtable_addr != 1:
                gadget_obj = builder.Obj64()
                gadget_obj.setVptr(vtable_addr, self.config.vptr_offset)
            else:
                gadget_obj = builder.Object(noFakeVtable=False, vFunc=gadget.rebased_addr, vIndex=self.config.vptr_offset)
        else:
            gadget_obj = builder.Obj64()
        object_data_hex = hex(object_data)[2:]
        if object_data_hex.endswith("L"):
            object_data_hex = object_data_hex[:-1]
        while len(object_data_hex)/2 < self.object_size:
            object_data_hex = "0" + object_data_hex
        offsets = []
        for ptr in self.pointers:
            h = hex(ptr)[2:]
            i = iter(h)
            pairs = zip(i,i)
            le_notation = "".join(["".join(p) for p in pairs[::-1]])
            offset = object_data_hex.find(le_notation)/2
            if offset == -1:
                print "Couldn't generate pointer offsets."
                return None
            offset_to_ptr = (ptr - self.self_pointer) - offset - 8
            this_label = hash(hash(ptr) + hash(object_data))
            gadget_obj.mem.addUnresolvedPointer(offset+8, this_label, offset_to_ptr, this_label)
            offsets.append(offset)

        bytes = solver_utils.int_to_bytes(object_data, self.object_size)
        if not offsets:
            gadget_obj.mem.addData(self.symbolic_object_offset, bytes)
        else:
            current_offset = 0
            for offset in offsets:
                if offset > current_offset:
                    res = gadget_obj.mem.addData(self.symbolic_object_offset+current_offset, bytes[current_offset:offset])
                current_offset = offset + 8
            res = gadget_obj.mem.addData(self.symbolic_object_offset+current_offset, bytes[current_offset:])
        logging.getLogger("autocoop.esl_lib.gadgets").info("[+] Valid {} gadget found".format(self.name))
        return vtable_addr, self.gadget_def, gadget_obj

    def valid_object(self, state, vtable_addr, gadget):
        """
        Steps to take after a valid object is found

        :param state: State after gadget is called
        :param vtable_addr: Vtable addr of gadget
        :param gadget: IR of gadget
        """
        pass

    def configure_state(self, state):
        """
        Configures the state as required by the solver

        :param state: State to check
        """
        pass

    def check_if_valid_state(self, state):
        """
        Returns true if a state is valid

        :param state: State to check
        """
        return state.satisfiable()

    def search(self):
        """
        Searches through the candidate set for valid gadgets and generates the gadget objects. This function should
        not be modified, instead modify the functions called by search.

        :yields: Gadget addresses and builder objects
        """
        if len(self.candidates) > 1000000:
            if self.name == "IF":
                candidates = self.candidates[1107:]
            elif self.name == "Write":
                candidates = self.candidates[281:]
            elif self.name == "READ":
                candidates = self.candidates[222:]
            else:
                candidates = self.candidates
        else:
            candidates = self.candidates

        length = len(candidates)
        counter = 0
        # from pympler.tracker import SummaryTracker
        # from pympler import asizeof
        # tracker = SummaryTracker()
        # size_self = asizeof.asizeof(self)
        for index, (vtable_addr, gadget) in list(enumerate([x for x in candidates])):
            # self.app.factory.block(gadget.rebased_addr).pp()
            if vtable_addr == 1:
                vtable_addr = candidate_finder.get_vtbl_address(self.app, gadget)
            counter += 1
            logging.getLogger("autocoop.esl_lib.gadgets").info(
                "[*] Evaluating potential {} gadget {}/{}: {}".format(self.name, counter, length, gadget))

            state = self.setup_state(gadget, vtable_addr)
            self.configure_state(state)
            try:
                simulation = self.simulate(state)
                for i in self.manage_resulting_states(simulation, vtable_addr, gadget):
                    yield i
                for i in simulation:
                    del i
                del simulation
            except angr.errors.SimUnsatError:
                pass
            gc.collect()
            # tracker.print_diff()
            # print asizeof.asizeof(self) - size_self
            # size_self = asizeof.asizeof(self)
        logging.getLogger("autocoop.esl_lib.gadgets").info("[-] {} search completed.".format(self.name))

    def manage_resulting_states(self, simulation, vtable_addr, gadget):
        yielded = False
        for resulting_state in simulation:
            self.add_constraints(resulting_state)
            self.add_postconditions(resulting_state, vtable_addr, gadget)
            if self.check_if_valid_state(resulting_state):
                obj = self.generate_object(resulting_state, vtable_addr, gadget)
                if obj:
                    if not self.config.other_args.get("gadgetcounts", None):
                        self.valid_object(resulting_state, vtable_addr, gadget)
                    yielded = True
                    yield obj
        if not yielded:
            if (vtable_addr, gadget) in self.app.kb.candidates[self.calltarget_id]:
                self.app.kb.candidates[self.calltarget_id].remove((vtable_addr, gadget))
            if (1, gadget) in self.app.kb.candidates[self.calltarget_id]:
                self.app.kb.candidates[self.calltarget_id].remove((1, gadget))

    @classmethod
    def filter_candidate_list(cls, app, candidates):
        """
        Further filter the candidate list based on the disassembly

        :param app: Parent angr project
        :param candidates: List of candidates to filter
        :param call: The concrete gadget
        :return:
        """
        for candidate in tqdm.tqdm(candidates):
            insns = capstone_utils.get_function_capstone(app, candidate[1])
            if cls.is_candidate_function(app, insns):
                yield candidate
        # return [candidate for candidate in candidates if cls.is_candidate_function(app, candidate[1])]


    @classmethod
    def is_candidate_function(cls, app, insns):
        """
        Semantic filtering based on disassembly, using only the gadget category, but no information like
        register assignments or concrete variable values.

        :param app: Parent angr project
        :param insns: List of instructions
        :return: True if gadget is valid gadget for this category
        :rtype: bool
        """
        if len(insns) > cls.sem_filter_max_size:
            return False
        if not insns or insns[-1].mnemonic != "ret":
            return False
        for insn in insns:
            if insn.mnemonic in cls.sem_filter:
                operands = insn.operands
                filter_ops = cls.sem_filter[insn.mnemonic]
                if len(operands) < len(filter_ops) and len(filter_ops) > 1:
                    continue
                for i, (filter_op, operand) in enumerate(zip(filter_ops, operands)):
                    if filter_op == "any":
                        continue
                    if filter_op == "mem":
                        if operand.type != arm64.ARM64_OP_MEM:
                            break
                    elif filter_op == "reg":
                        if operand.type != arm64.ARM64_OP_REG:
                            break
                    elif filter_op == "imm":
                        if operand.type != arm64.ARM64_OP_IMM:
                            break
                else:
                    return True
            if insn.mnemonic in cls.sem_blacklist:
                operands = insn.operands
                filter_ops = cls.sem_blacklist[insn.mnemonic]
                if len(operands) < len(filter_ops) and len(filter_ops) > 1:
                    continue
                for i, (filter_op, operand) in enumerate(zip(filter_ops, operands)):
                    if filter_op == "any":
                        continue
                    if filter_op == "mem":
                        if operand.type != arm64.ARM64_OP_MEM:
                            break
                    elif filter_op == "reg":
                        if operand.type != arm64.ARM64_OP_REG:
                            break
                    elif filter_op == "imm":
                        if operand.type != arm64.ARM64_OP_IMM:
                            break
                else:
                    return False
