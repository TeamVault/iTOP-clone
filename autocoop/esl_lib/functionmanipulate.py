import autocoop.esl_lib.lib_utils.function_gadget_base as function_gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64

class Manipulate(function_gadget_base.FunctionGadget):
    name = "MANIPULATE"

    def valid_object(self, state, gadget):
        target_register = solver_utils.resolve_reg(self.gadget_def.args[0].name)
        value = state.solver.eval(state.regs.__getattr__(target_register))
        for i in range(len(self.gadget_def.assignments)):
            if self.gadget_def.assignments[i].name == self.gadget_def.args[0].name:
                self.gadget_def.assignments[i].value = value

    @classmethod
    def is_candidate_gadget(cls, app, candidate, call):
        # any register is changed
        read_from = set()
        for arg in call.args:
            if arg.value is None and arg.name.startswith("_r"):
                read_from.update(solver_utils.alternatives(solver_utils.resolve_reg(arg.name)))
        conds = set()
        for arg in call.postconditions:
            for operand in arg:
                if callable(getattr(operand, "startswith", None)) and operand.startswith("_r"):
                    conds.update(solver_utils.alternatives(solver_utils.resolve_reg(operand)))
        write_to = read_from.intersection(conds)
        dont_change = conds - read_from
        insns = capstone_utils.get_function_capstone(app, candidate)
        if insns[-1].mnemonic != "ret":
            return False
        manipulated = set()
        for insn in insns:
            if insn.mnemonic == "call":
                return False
            if insn.mnemonic.startswith("mov") or insn.mnemonic in ("mov", "lea", "add", "sub", "inc", "dec", "imul", "idiv", "and", "or", "xor", "not", "neg", "shl", "shr"):
                if insn.operands and insn.operands[0].type == arm64.ARM64_OP_REG and insn.reg_name(insn.operands[0].reg) in (write_to | dont_change):
                    manipulated.update(solver_utils.alternatives(insn.reg_name(insn.operands[0].reg)))
        for insn in insns[::-1]:
            if insn.mnemonic == "pop" and insn.operands and insn.reg_name(insn.operands[0].reg) in manipulated:
                manipulated.difference_update(solver_utils.alternatives(insn.reg_name(insn.operands[0].reg)))
        return (not (manipulated ^ write_to)) and (not (dont_change & manipulated))

    @classmethod
    def is_candidate_function(cls, app, candidate):
        # any register is changed
        insns = capstone_utils.get_function_capstone(app, candidate)
        if not insns:
            return False
        if insns[-1].mnemonic != "ret":
            return False
        manipulated = set()
        for insn in insns:
            if insn.mnemonic == "call":
                return False
            if insn.mnemonic.startswith("mov") or insn.mnemonic in (
            "mov", "lea", "add", "sub", "inc", "dec", "imul", "idiv", "and", "or", "xor", "not", "neg", "shl", "shr"):
                if insn.operands and insn.operands[0].type == arm64.ARM64_OP_REG:
                    manipulated.update(solver_utils.alternatives(insn.reg_name(insn.operands[0].reg)))
        for insn in insns[::-1]:
            if insn.mnemonic == "pop" and insn.operands and insn.reg_name(insn.operands[0].reg) in manipulated:
                manipulated.difference_update(solver_utils.alternatives(insn.reg_name(insn.operands[0].reg)))
        return bool(manipulated)

gadget = Manipulate