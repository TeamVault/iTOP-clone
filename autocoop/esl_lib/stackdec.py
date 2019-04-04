import autocoop.esl_lib.lib_utils.gadget_base as gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64

class Stackinc(gadget_base.Gadget):
    name = "STACKDEC"
    sem_filter = {
                  "add": ("reg", "any"),
                  "sub": ("reg", "any"),
                  "inc": ("reg",),
                  "dec": ("reg",),
                  }

    def configure_state(self, state):
        self.rsp = state.solver.eval(state.regs.rsp)

    def add_constraints(self, state):
        state.solver.add(state.regs.rsp == self.rsp) # +0 because 8 are taken from stack when function is left


gadget = Stackinc