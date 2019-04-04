import autocoop.esl_lib.lib_utils.gadget_base as gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64

class Manipulate(gadget_base.Gadget):
    name = "INC"
    sem_filter = {"add": ("reg", "any"),
                  "sub": ("reg", "any"),
                  "inc": ("reg",),
                  "dec": ("reg",),
                  }

    def configure_state(self, state):
        target_register = solver_utils.resolve_reg(self.gadget_def.args[0].name)
        self.target_so = state.solver.BVS("target_so", 64)
        state.solver.add(state.regs.__getattr__(target_register) == self.target_so)


    def valid_object(self, state, vtable_addr, gadget):
        target = None
        for assignment in self.gadget_def.assignments:
            if assignment.value == None and assignment.name.startswith("_r"):
                target = assignment
                break
        if not target:
            return
        target_register = solver_utils.resolve_reg(target.name)
        value = state.solver.eval(state.regs.__getattr__(target_register))
        state.solver.add(self.target_so == self.gadget_def.args[0].value)
        for assignment in self.gadget_def.assignments:
            if assignment.name == target.name:
                assignment.value = value
        else:
            cpy = self.gadget_def.args[0].copy()
            cpy.value = value
            self.gadget_def.assignments.append(cpy)

    def check_if_valid_state(self, state):
        target_register = solver_utils.resolve_reg(self.gadget_def.args[0].name)
        if not state.solver.satisfiable():
            return False
        so = state.solver.eval(self.symbolic_object)
        target_reg = state.regs.__getattr__(target_register)
        state.solver.add(self.symbolic_object == so)
        if state.solver.satisfiable([self.target_so==5, target_reg==6]) and state.solver.satisfiable([self.target_so==6, target_reg==7]):
            return True
        return False

    def add_constraints(self, state):
        target_register = solver_utils.resolve_reg(self.gadget_def.args[0].name)
        target_value = self.gadget_def.args[0].value
        state.solver.add(state.regs.__getattr__(target_register) == self.target_so+1)

    def ensure_preconditions(self, state, gadget_def):
        for assignment in gadget_def.assignments[::-1]:
            if assignment.name.startswith("_r") and assignment.value:
                if assignment.name != self.gadget_def.args[0].name:
                    state.regs.__setattr__(solver_utils.resolve_reg(assignment.name), assignment.value)


gadget = Manipulate