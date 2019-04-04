"""
Gadgets that writes a value to an address
"""

import autocoop.esl_lib.lib_utils.gadget_base as gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64
import autocoop.esl_lib.lib_utils.angr_extensions as angr_extensions

class Write(gadget_base.Gadget):
    name = "Write"
    sem_filter = {"mov": ("mem", "any"),
                  "movsx": ("mem", "any"),
                  "movsxd": ("mem", "any"),
                  "movs": ("mem", "any"),
                  "movsb": ("mem", "any"),
                  "movsw": ("mem", "any"),
                  "movsd": ("mem", "any"),
                  "movsq2": ("mem", "any")}

    def configure_state(self, state):
        self.target_addr = self.gadget_def.args[0].value
        self.target_value = self.gadget_def.args[1]
        state.memory.write_strategies.insert(0, angr_extensions.ResolveSingleAddress(self.target_addr))


    def add_constraints(self, state):
        if self.target_value.is_ptr:
            state.solver.add(state.memory.load(state.memory.load(self.target_addr, 8)) == self.target_value.value)
        else:
            state.solver.add(state.memory.load(self.target_addr, 8) == self.target_value.value)

gadget = Write