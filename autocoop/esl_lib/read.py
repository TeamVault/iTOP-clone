import archinfo

import autocoop.esl_lib.lib_utils.gadget_base as gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64
import autocoop.esl_lib.lib_utils.angr_extensions as angr_extensions
import angr


class Read(gadget_base.Gadget):
    name = "READ"
    sem_filter = {"mov": ("reg", "any"),
                  "lea": ("reg",),
                  "movsx": ("reg", "any"),
                  "movsxd": ("reg", "any"),
                  "movs": ("reg", "any"),
                  "movsb": ("reg", "any"),
                  "movsw": ("reg", "any"),
                  "movsd": ("reg", "any"),
                  "movsq2": ("reg", "any")}

    def add_constraints(self, state):
        target_register = solver_utils.resolve_reg(self.gadget_def.assignments[0].name)
        state.solver.add(state.regs.__getattr__(target_register) != 0)

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
        for assignment in self.gadget_def.assignments:
            if assignment.name == target.name:
                assignment.value = value

    def check_if_valid_state(self, state):
        target_register = solver_utils.resolve_reg(self.gadget_def.assignments[0].name)
        if not state.satisfiable():
            return False
        so = state.solver.eval(self.symbolic_object)
        state.solver.add(self.symbolic_object == so)
        if len(state.solver.eval_upto(state.regs.__getattr__(target_register), 2)) != 1:
            return False
        res = state.solver.eval_upto(state.memory.load(self.self_pointer+0x10, 8, endness=archinfo.Endness.LE), 2)
        if len(res) == 1:
            res = res[0]
            for postcondition in self.gadget_def.postconditions:
                if not type(postcondition[2]) == int:
                    print postcondition
                    val, ptr = solver_utils.get_from_assignments(self.gadget_def.assignments, postcondition[2])
                else:
                    val = postcondition[2]
                if val == res:
                    self.pointers[self.self_pointer+0x10] = res
        return True

    def configure_state(self, state):
        state.memory.read_strategies.insert(0, angr_extensions.ResolveSingleAddress(self.self_pointer + 0x10))
        state.memory.read_strategies.append(angr.state_plugins.symbolic_memory.concretization_strategies.single.SimConcretizationStrategySingle())


gadget = Read