"""
Gadgets that loads the value from an address in memory into a register
"""

import autocoop.esl_lib.lib_utils.gadget_base as gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64
import autocoop.esl_lib.lib_utils.angr_extensions as angr_extensions
import angr

class Load(gadget_base.Gadget):
    name = "LOAD"
    sem_filter = {"mov": ("reg", "mem"),
                  "movsx": ("reg", "mem"),
                  "movsxd": ("reg", "mem"),
                  "movs": ("reg", "mem"),
                  "movsb": ("reg", "mem"),
                  "movsw": ("reg", "mem"),
                  "movsd": ("reg", "mem"),
                  "movsq2": ("reg", "mem")}

    def configure_state(self, state):
        target_addr = self.gadget_def.args[0].value
        self.target_bv = state.solver.BVS("target_bv", 64)
        state.memory.store(target_addr, self.target_bv)
        state.solver.add(self.target_bv == 0xdeadbeefbabecafe)
        state.memory.read_strategies.insert(0, angr_extensions.ResolveSingleAddress(target_addr))
        state.memory.read_strategies.append(angr.state_plugins.symbolic_memory.concretization_strategies.single.SimConcretizationStrategySingle())

    def check_if_valid_state(self, state):
        target_register = solver_utils.resolve_reg(self.gadget_def.assignments[0].name)
        return state.solver.is_true(self.target_bv.reversed == state.regs.__getattr__(target_register))

    # def add_constraints(self, state):
    #     target_register = solver_utils.resolve_reg(self.gadget_def.assignments[0].name)
    #     state.solver.add(self.target_bv.reversed == state.regs.__getattr__(target_register))

gadget = Load