import autocoop.esl_lib.lib_utils.function_gadget_base as function_gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64


class Read(function_gadget_base.FunctionGadget):
    name = "READ"

    def add_constraints(self, state):
        target_register = solver_utils.resolve_reg(self.gadget_def.assignments[0].name)
        state.solver.add(state.regs.__getattr__(target_register) != 0)

    def valid_object(self, state, gadget):
        target_register = solver_utils.resolve_reg(self.gadget_def.assignments[0].name)
        value = state.solver.eval(state.regs.__getattr__(target_register))
        self.gadget_def.assignments[0].value = value

    # def get_candidates(self):
    #     return gadget_base.Gadget.get_candidates(self)[78:]

    @classmethod
    def is_candidate_gadget(cls, app, candidate, call):
        target_reg = None
        for arg in call.assignments:
            target_reg = solver_utils.alternatives(solver_utils.resolve_reg(arg.name))
        if not target_reg:
            return False
        insns = capstone_utils.get_function_capstone(app, candidate)
        if insns[-1].mnemonic != "ret":
            return False
        write_found = False
        for insn in insns:
            if insn.mnemonic == "call":
                return False
            if not write_found and ("mov" in insn.mnemonic or insn.mnemonic in ("mov", "lea", "add", "sub", "inc", "dec", "imul", "idiv", "and", "or", "xor", "not", "neg", "shl", "shr")) and len(insn.operands) > 1:
                if insn.operands[0].type == arm64.ARM64_OP_REG and insn.reg_name(insn.operands[0].reg) in target_reg:
                    write_found = True
            elif write_found:
                if insn.mnemonic in ("pop") and insn.operands and insn.operands[0].type == arm64.ARM64_OP_REG and insn.reg_name(insn.operands[0].reg) in target_reg:
                    write_found = False
        return write_found

    @classmethod
    def is_candidate_function(cls, app, candidate):
        insns = capstone_utils.get_function_capstone(app, candidate)
        if not insns:
            return False
        if insns[-1].mnemonic != "ret":
            return False
        written = set()
        for insn in insns:
            if insn.mnemonic == "call":
                return False
            if ("mov" in insn.mnemonic or insn.mnemonic in ( "mov", "lea", "add", "sub", "inc", "dec", "imul", "idiv", "and", "or", "xor", "not", "neg", "shl","shr")) and len(insn.operands) > 1:
                if insn.operands[0].type == arm64.ARM64_OP_REG:
                    written.add(insn.operands[0].reg)
            elif insn.mnemonic in ("pop") and insn.operands and insn.operands[0].type == arm64.ARM64_OP_REG and insn.operands[0].reg in written:
                written.remove(insn.operands[0].reg)
        return bool(written)

gadget = Read