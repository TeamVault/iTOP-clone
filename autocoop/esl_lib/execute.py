import logging
import signal

import autocoop.esl_lib.lib_utils.gadget_base as gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64


class Execute(gadget_base.Gadget):
    name = "EXECUTE"
    sem_filter = {"call": ("any", )}
    sem_blacklist = {}

    def simulate(self, state):
        def timeout_handler(signum, frame):
            raise Exception("timeout")
        simgr = self.app.factory.simgr(state, save_unconstrained=True)
        simgr.use_technique(solver_utils.CheckUniquenessAndFind(find=self.gadget_def.args[0].value, avoid=0x0))
        try:
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
        except Exception as e:
            return []
        return simgr.active + simgr.unconstrained

    def add_constraints(self, state):
        state.solver.add(state.regs.ip == self.gadget_def.args[0].value)
        solver_utils.ensure_args(self, state, self.gadget_def.args[1:])

    def add_postconditions(self, state, vtable_addr, gadget):
        pass

    # def get_candidates(self):
    #     return gadget_base.Gadget.get_candidates(self)[3849:]

    @classmethod
    def is_candidate_gadget(cls, app, candidate, call):
        if not call.args:
            return False
        target_fn = call.args[0].value
        insns = capstone_utils.get_function_capstone(app, candidate)
        for insn in insns:
            if insn.mnemonic == "call":
                if insn.operands and insn.operands[0].type == arm64.ARM64_OP_IMM:
                    if insn.operands[0].imm == target_fn:
                        return True
                elif insn.operands:
                    return True
        return False

    @classmethod
    def is_candidate_function(cls, app, insns):
        for insn in insns:
            if insn.mnemonic == "call":
                if insn.operands and insn.operands[0].type == arm64.ARM64_OP_IMM:
                    return True
                elif insn.operands:
                    return True
        return False

gadget = Execute
