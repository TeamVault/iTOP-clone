"""
Gadgets that writes a value to an address
"""

import autocoop.esl_lib.lib_utils.gadget_base as gadget_base
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
from capstone import arm64
import autocoop.esl_lib.lib_utils.angr_extensions as angr_extensions
import claripy
import logging
import autocoop.builder.builder as builder

class If(gadget_base.Gadget):
    name = "IF"
    sem_filter = {"mov": ("mem", "any"),
                  "movsx": ("mem", "any"),
                  "movsxd": ("mem", "any"),
                  "movs": ("mem", "any"),
                  "movsb": ("mem", "any"),
                  "movsw": ("mem", "any"),
                  "movsd": ("mem", "any"),
                  "movsq2": ("mem", "any")}

    def configure_state(self, state):
        self.target_addr = self.app.kb.if_object_offset
        self.app.kb.if_object_offset += self.app.kb.if_object_inc
        self.target_value = self.app.kb.if_object_offset
        state.memory.write_strategies.insert(0, angr_extensions.ResolveSingleAddress(self.target_addr))
        self.registers["rsi"] = None


    def manage_resulting_states(self, simulation, vtable_addr, gadget):
        if len(simulation) != 2:
            if (vtable_addr, gadget) in self.app.kb.candidates[self.calltarget_id]:
                self.app.kb.candidates[self.calltarget_id].remove((vtable_addr, gadget))
            if (1, gadget) in self.app.kb.candidates[self.calltarget_id]:
                self.app.kb.candidates[self.calltarget_id].remove((1, gadget))
            return

        left = simulation[0]

        reg = left.regs.__getattr__(solver_utils.resolve_reg(self.gadget_def.condition[0]))
        cmpops = {
            "==": reg.__eq__,
            ">": reg.__gt__,
            "<": reg.__lt__
        }
        cmpop = cmpops[self.gadget_def.condition[1]]
        value = self.gadget_def.condition[2]
        condition1_left = cmpop(value)
        condition2_left = left.memory.load(self.target_addr, 8) == self.target_value


        right = simulation[1]
        reg = right.regs.__getattr__(solver_utils.resolve_reg(self.gadget_def.condition[0]))
        cmpops = {
            "==": reg.__eq__,
            ">": reg.__gt__,
            "<": reg.__lt__
        }
        cmpop = cmpops[self.gadget_def.condition[1]]
        value = self.gadget_def.condition[2]
        condition1_right = cmpop(value)
        condition2_right = right.memory.load(self.target_addr, 8) == self.target_value

        if not left.solver.is_false(condition2_left):
            left_is_true_branch = True
        elif not right.solver.is_false(condition2_right):
            left_is_true_branch = False
        else:
            # self.app.factory.block(gadget.rebased_addr, gadget.size).pp()
            if (vtable_addr, gadget) in self.app.kb.candidates[self.calltarget_id]:
                self.app.kb.candidates[self.calltarget_id].remove((vtable_addr, gadget))
            if (1, gadget) in self.app.kb.candidates[self.calltarget_id]:
                self.app.kb.candidates[self.calltarget_id].remove((1, gadget))
            return

        if left_is_true_branch:
            object_data = left.solver.eval(self.symbolic_object, extra_constraints=[condition1_left, condition2_left])
        else:
            object_data = right.solver.eval(self.symbolic_object, extra_constraints=[condition1_right, condition2_right])


        left.solver.add(self.symbolic_object == object_data)
        right.solver.add(self.symbolic_object == object_data)
        if left_is_true_branch:
            r1 = left.solver.satisfiable(extra_constraints=[condition1_left, condition2_left])
            r2 = right.solver.satisfiable(
                extra_constraints=[claripy.Not(condition1_right), claripy.Not(condition2_right)])
            r3 = left.solver.satisfiable(extra_constraints=[claripy.Not(condition1_left), condition2_left])
        else:
            r1 = right.solver.satisfiable(extra_constraints=[condition1_right, condition2_right])
            r2 = left.solver.satisfiable(
                extra_constraints=[claripy.Not(condition1_left), claripy.Not(condition2_left)])
            r3 = right.solver.satisfiable(extra_constraints=[claripy.Not(condition1_right), condition2_right])
        if r1 and r2:
            gadget.target_addr = self.target_addr
            gadget.target_value = self.target_value
            if left_is_true_branch:
                obj = self.generate_object(left, vtable_addr, gadget)
            else:
                obj = self.generate_object(right, vtable_addr, gadget)
            if obj:
                yield obj
            else:
                if (vtable_addr, gadget) in self.app.kb.candidates[self.calltarget_id]:
                    self.app.kb.candidates[self.calltarget_id].remove((vtable_addr, gadget))
                if (1, gadget) in self.app.kb.candidates[self.calltarget_id]:
                    self.app.kb.candidates[self.calltarget_id].remove((1, gadget))
        else:
            if (vtable_addr, gadget) in self.app.kb.candidates[self.calltarget_id]:
                self.app.kb.candidates[self.calltarget_id].remove((vtable_addr, gadget))
            if (1, gadget) in self.app.kb.candidates[self.calltarget_id]:
                self.app.kb.candidates[self.calltarget_id].remove((1, gadget))


    def generate_object(self, state, vtable_addr, gadget):
        if state.solver.satisfiable():
            object_data = state.solver.eval(self.symbolic_object)
        else:
            return None
        state.solver.add(self.symbolic_object == object_data)
        for reg, bv in self.registers.items():
            if bv != None:
                if len(state.solver.eval_upto(bv, 2)) < 2:
                    if state.solver.eval(bv) == self.target_addr:
                        continue
                    logging.getLogger("autocoop.esl_lib.gadgets").info("[*] Gadget {} depends on register initialization".format(self.name))
                    return None
        if vtable_addr != 1:
            gadget_obj = builder.Obj64()
            gadget_obj.setVptr(vtable_addr, self.config.vptr_offset)
        else:
            gadget_obj = builder.Object(noFakeVtable=False, vFunc=gadget.rebased_addr, vIndex=self.config.vptr_offset)
        bin_data = solver_utils.int_to_bytes(object_data, 0x60)
        to_find = solver_utils.int_to_bytes(self.target_addr, 8)[::-1]
        offset = bin_data.find(to_find)
        to_find2 = solver_utils.int_to_bytes(self.target_value, 8)
        offset2 = bin_data.find(to_find2)
        switched = False
        if offset > offset2:
            offset, offset2 = offset2, offset
            switched = True
        if offset > 0:
            gadget_obj.mem.addData(0x8, bin_data[0:offset])
        if offset2 > offset+8:
            gadget_obj.mem.addData(0x8+offset+0x8, bin_data[offset+8:offset2])
        gadget_obj.mem.addData(0x8+offset2+0x8, bin_data[offset2+8:])
        if switched:
            offset, offset2 = offset2, offset
        if offset >= 0:
            gadget_obj.mem.addUnresolvedPointer(0x8+offset, self.app.kb.initial_object_label, self.app.kb.next_node_offset)
        if offset2 >= 0:
            gadget_obj.mem.addUnresolvedPointer(0x8+offset2, self.target_value)
        self.gadget_def.target_addr_label = self.target_addr
        self.gadget_def.target_value = self.target_value
        logging.getLogger("autocoop.esl_lib.gadgets").info("[+] Valid {} gadget found".format(self.name))
        return vtable_addr, self.gadget_def, gadget_obj

    def ensure_preconditions(self, state, gadget_def):
        for assignment in gadget_def.assignments[::-1]:
            if assignment.name.startswith("_r") and assignment.value:
                if assignment.name != self.gadget_def.condition[0]:
                    state.regs.__setattr__(solver_utils.resolve_reg(assignment.name), assignment.value)


gadget = If