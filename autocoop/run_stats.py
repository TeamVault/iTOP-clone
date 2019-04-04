import autocoop.exploit_generator as exploit_generator
from autocoop.esl.parser import StatementParser
import os
import time
import logging
import utils.utils as utils
import csv
import pprint

def payload_stats(payload):
    parser = exploit_generator.Parser(payload)
    chains = list(build_chains(tuple(parser.main_calls.calls)))
    chains.sort(key=len)
    for chain in chains:
        print "++++++++++++++++++++++++++++++++++++++++"
        for gadget in chain:
            print gadget[1], " args: ", gadget[0].args, " assignments: ", gadget[0].assignments
    return len(chains), len(chains[0]), len(chains[-1])

def build_chains(rest):
    if not rest:
        yield tuple()
        return
    next_call = rest[0]
    new_rest = rest[1:]
    for fn in next_call.function:
        if type(fn) == StatementParser:
            for i, argument in enumerate(fn.assignments):
                if len(next_call.args) <= i:
                    break
                argument.value = next_call.args[i].value
                argument.is_ptr = next_call.args[i].is_ptr
            if next_call.label:
                fn.calls[0].label = next_call.label
            fn.calls[0].assignments.extend(fn.assignments)
            new_calls = []
            for call in fn.calls:
                new_calls.append(call.copy())
            for chain in build_chains(tuple(new_calls) + new_rest):
                yield chain
        else:
            for chain in build_chains(new_rest):
                yield ((next_call, fn),) + chain


payloads = [
    "esl_scripts/testsuite_coop/regset.esl",
    "esl_scripts/testsuite_coop/memrd.esl",
    "esl_scripts/testsuite_coop/memwrt.esl",
    "esl_scripts/testsuite_coop/regadd.esl",
    # "esl_scripts/testsuite_coop/stkadd.esl",
    # "esl_scripts/testsuite_coop/stkdec.esl",
    "esl_scripts/testsuite_coop/printf.esl",
    "esl_scripts/testsuite_coop/shell.esl",
    "esl_scripts/testsuite_coop/iloop.esl",
    "esl_scripts/testsuite_coop/cond.esl",
    "esl_scripts/testsuite_coop/for.esl",
    "esl_scripts/testsuite_coop/cshell.esl",
    # "esl_scripts/testsuite_coop/count.esl",
    # "esl_scripts/testsuite_coop/fib.esl",
    # "esl_scripts/testsuite_coop/memprt.esl",
    # "esl_scripts/testsuite_coop/env.esl",
]

if __name__ == '__main__':
    for payload in payloads:
        print payload, payload_stats(payload)