from autocoop.builder.function_builder import ArrayBuilder, Arch, Obj64, Object
import autocoop.esl_lib.lib_utils.candidate_finder as candidate_finder
import autocoop.esl_lib.lib_utils.capstone_utils as capstone_utils
import logging
import angr
from capstone import arm64
import itertools

def generate_main(app, config, calltargets_order):
    """
    Finds the function dispatch loop and generates the builder.

    The the offsets for the function array ptr and the function array length are generated by stepping though the
    disassembled code, from the virtual function call/the loop exit condition, tracking the relevant registers until
    the offset is found.

    :param angr.Project app: application the gadget will be found for
    :param Config config: configuration of the exploit generator
    :param list[int] calltargets_order: list of calltargets in the order they are called in
    :return: Array builder object ready for more objects to be added and vptr offset

    """
    logger = logging.getLogger("autocoop.esl_lib.mainloop")
    logger.info("[*] Building Callsite Candidate Set")
    # app.analyses.CFGFast()
    # candidates = list(candidate_finder.get_candidate_callsites_from_csv(app, config.other_args["gadget_csv"]))
    candidates = list(candidate_finder.get_all_functions(app))
    for vtable, gadget in candidates:
        logger.info("[*] Evaluating potential FUNCTIONDISPATCH gadget: {}".format(gadget))
        # print "++++++++++++++++++++++++++++++++++++++++++++"
        insns = capstone_utils.get_function_capstone(app, gadget)
        # find gadget array offset
        # 1. seek forward until call is found
        # 2. find the registers relevant to the call
        call_index = -1
        while call_index+1 < len(insns):
            call_index += 1
            if insns[call_index].mnemonic == "call":
                logger.info("[!] Finished step 1 (find call): {}".format(gadget))
                call_ins = insns[call_index]
                if call_ins.mnemonic != "call":
                    continue
                if len(call_ins.operands) != 1:
                    continue
                operand = call_ins.operands[0]
                if operand.type != arm64.ARM64_OP_MEM:
                    continue
                if operand.mem.base == 0:
                    continue
                logger.info("[!] Finished step 2 (find relevant registers): {}".format(gadget))
                loop_counter = operand.mem.index
                if not loop_counter:
                    continue
                array_offset = [operand.mem.disp]
                if not array_offset[0]:
                    array_offset = []
                invalid = False
                assignment_index = call_index
                reg = operand.mem.base
                while assignment_index > 0:
                    assignment_index -= 1
                    res = capstone_utils.find_reg_source(insns[assignment_index], reg)
                    if not res:
                        continue
                    reg, array_offset_tmp, _, _ = res
                    if array_offset_tmp:
                        array_offset.append(array_offset_tmp)
                else:
                    if invalid or not array_offset:
                        continue
                logger.info("[!] Finished step 3 (find loop counter and array offset): {}".format(gadget))

                # find gadget loop condition offset
                # 4. identify loop exit condition
                # 5. go back through the instructions

                condition_index = call_index
                visited = set()
                reg = None
                invalid = False
                while condition_index and condition_index + 1 < len(insns) and condition_index + 1 not in visited:
                    condition_index += 1
                    visited.add(condition_index)
                    insn = insns[condition_index].insn
                    if insn.mnemonic == "jmp":
                        if insn.operands[0].type == arm64.ARM64_OP_IMM:
                            target = insn.operands[0].imm
                            condition_index = capstone_utils.find_index_for_addr(insns, target)
                    elif insn.mnemonic.startswith("j"):
                        if capstone_utils.find_index_for_addr(insns, insn.operands[0].imm) <= call_index:
                            condition_index -= 1
                            insn = insns[condition_index].insn
                            if insn.mnemonic == "cmp":
                                if insn.operands[0].type == arm64.ARM64_OP_REG and insn.operands[
                                    1].type == arm64.ARM64_OP_REG:
                                    if insn.operands[0].reg == loop_counter:
                                        reg = insn.operands[1].reg
                                    elif insn.operands[1].reg == loop_counter:
                                        reg = insn.operands[0].reg
                                    break
                            else:
                                invalid = True
                else:
                    continue
                if invalid:
                    continue
                logger.info("[!] Finished step 4 (find loop exit condition): {}".format(gadget))

                condition_offset = []
                assignment_index = condition_index
                while assignment_index > 0:
                    assignment_index -= 1
                    res = capstone_utils.find_reg_source(insns[assignment_index], reg)
                    if not res:
                        continue
                    reg, condition_offset_tmp, _, _ = res
                    if condition_offset_tmp:
                        condition_offset.append(condition_offset_tmp)
                else:
                    if not condition_offset:
                        continue

                logger.info("[!] Finished step 5 (find loop exit condition offset): {}".format(gadget))

                capstone_utils.get_function_capstone(app, gadget)

                if vtable == 1:
                    initObj = Object(vIndex=0, vFunc=vtable, noFakeVtable=False, fixedOffset=0)
                else:
                    initObj = Obj64(fixedOffset=0)
                    initObj.setVptr(vtable)

                same_object = 1
                count = 0
                depth_cond = len(condition_offset)
                depth_array = len(array_offset)
                label_offset_cond = 25
                label_offset_array = 50
                objects = []

                def add_link_to_next(offset, count, label_offsets):
                    if count == 1:
                        obj = initObj
                    else:
                        obj = Obj64()
                        for label_offset in label_offsets:
                            obj.mem.addLabel(0, 0, count - 1 + label_offset)
                    for label_offset in label_offsets:
                        obj.mem.addUnresolvedPointer(offset=offset, targetLabel=count + label_offset)
                    if count > 1:
                        objects.append(obj)

                for cond, array in itertools.izip_longest(condition_offset[::-1], array_offset[::-1]):
                    count += 1
                    if cond != array:
                        same_object = 0
                    if same_object == 1:
                        add_link_to_next(array, count, [label_offset_array, label_offset_cond])
                    else:
                        if count == depth_cond:
                            if count == 1:
                                obj = initObj
                            else:
                                obj = Obj64()
                                obj.mem.addLabel(0, 0, count - 1 + label_offset_cond)
                            obj.mem.addQword(offset=cond, qword=len(calltargets_order))
                            if count > 1:
                                objects.append(obj)
                        else:
                            if cond:
                                add_link_to_next(cond, count, [label_offset_cond])
                        if count == depth_array:
                            if count == 1:
                                obj = initObj
                            else:
                                if same_object != 0:
                                    obj = Obj64()
                                    obj.mem.addLabel(0, 0, count - 1 + label_offset_array)
                                else:
                                    obj = objects[-1]
                                    obj.mem.addLabel(0, 0, count - 1 + label_offset_array)
                            obj.mem.addUnresolvedPointer(array, targetLabel=ArrayBuilder.LABEL_ARRAY)
                            if count > 1 and same_object != 0:
                                objects.append(obj)
                        else:
                            if array:
                                add_link_to_next(array, count, [label_offset_array])
                        if same_object == 0:
                            same_object = -1

                b = ArrayBuilder(Arch.X64, config.base_buf, initObj)
                for obj in objects:
                    b.addObj(obj)
                calltargets = candidate_finder.get_all_functions(app)

                # import IPython; IPython.embed()
                yield b, gadget, calltargets
        else:
            continue
    raise StopIteration("No candidate callsites left.")


def update_main(array_builder, calltargets):
    """
    Adds objects to array builder

    :param array_builder: Array builder to add objects to
    :param list calltargets: list of calltargets and builder objects
    """
    for addr in calltargets:
        array_builder.addFunction(addr)


gadget = generate_main, update_main
