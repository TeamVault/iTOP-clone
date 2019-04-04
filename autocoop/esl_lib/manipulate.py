import autocoop.esl_lib.lib_utils.gadget_base as gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64

class Manipulate(gadget_base.Gadget):
    name = "MANIPULATE"
    sem_filter = {"mov": ("reg", "any"),
                  "lea": ("reg",),
                  "movsx": ("reg", "any"),
                  "movsxd": ("reg", "any"),
                  "movs": ("reg", "any"),
                  "movsb": ("reg", "any"),
                  "movsw": ("reg", "any"),
                  "movsd": ("reg", "any"),
                  "add": ("reg", "any"),
                  "sub": ("reg", "any"),
                  "inc": ("reg",),
                  "dec": ("reg",),
                  "imul": ("reg", "any"),
                  "idiv": ("reg", "any"),
                  "and": ("reg", "any"),
                  "xor": ("reg", "any"),
                  "or": ("reg", "any"),
                  "neg": ("reg",),
                  "not": ("reg",),
                  "shl": ("reg", "any"),
                  "shr": ("reg", "any"),
                  }

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


gadget = Manipulate