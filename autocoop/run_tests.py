import autocoop.exploit_generator as exploit_generator
import os
import time
import logging
import utils.utils as utils
import csv
import pprint

def test_one_payload(payload, binary):
    time_start = time.time()
    try:
        filename = "results/"+binary.split("/")[-1] + "/"+payload.split("/")[-1][:-4]
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        program = exploit_generator.Parser(payload)
        res = explgen.generate_payload(program)
        data = ["done"]
        utils.print_region(config.base_buf, int(res.encode("hex"), 16), len(res))
        f = open(filename, "wb")
        f.write(res)
        f.close()
        data = ["successful"]
    except Exception as e:
        data = ["error: " + str(e.message)]
    time_end = time.time()
    time_elapsed = time_end - time_start
    return [payload.split("/")[-1][:-4], time_elapsed] + data

payloads = [
    #"esl_scripts/testsuite_coop/regset.esl",
    # "esl_scripts/testsuite_coop/memrd.esl",
    # "esl_scripts/testsuite_coop/memwrt.esl",
    # "esl_scripts/testsuite_coop/regadd.esl",
    #"esl_scripts/testsuite_coop/printf.esl",
    "esl_scripts/testsuite_coop/shell.esl",
    # "esl_scripts/testsuite_coop/iloop.esl",
    # "esl_scripts/testsuite_coop/cond.esl",
    # "esl_scripts/testsuite_coop/for.esl",
    # "esl_scripts/testsuite_coop/cshell.esl",
    # "esl_scripts/testsuite_coop/count.esl",
    # "esl_scripts/testsuite_coop/fib.esl",
    # "esl_scripts/testsuite_coop/mprt.esl",
    # "esl_scripts/testsuite_coop/env.esl",
]

# target_binary = "exploitable_app/nodejs/libnode.so"
# # target_csv="exploitable_app/nodejs/SDOutput/libnode.so.57-Virtual-metric.csv"
# #
# target_binary = "exploitable_app/testapp/cmake-build-debug/libAPP.so"
# target_csv = "exploitable_app/testapp/cmake-build-debug/SDOutput/libAPP.so-Virtual-metric.csv"

# target_binary = "exploitable_app/nginx/build/sbin/nginx"
#target_binary = "exploitable_app/firefox/libxul.so"
# "exploitable_app/nodejs/libnode.so",

target_binaries = [
# "exploitable_app/nodejs/libnode.so",
# "exploitable_app/libtorrent/libtorrent.so",
# "exploitable_app/proftpd/proftpd",
# "exploitable_app/redis/redis-server",
# "exploitable_app/nginx/build/sbin/nginx",
# # "exploitable_app/apache2/apache2",
# "exploitable_app/apache2/httpd",
#    "exploitable_app/firefox/libxul.so", "exploitable_app/chromium/chrome"
    ("exploitable_app/nginx_1_14_2/nginx", "exploitable_app/nginx_1_14_2/calltargets.csv"),
#    ("exploitable_app/apache2/httpd", "exploitable_app/apache2/calltargets.csv"),
    ("exploitable_app/ffmpeg/ffmpeg_g", "exploitable_app/ffmpeg/calltargets.csv"),
    ("exploitable_app/opensshd/ssh", "exploitable_app/opensshd/calltargets.csv"),
    ("exploitable_app/php/php", "exploitable_app/php/calltargets.csv"),
    ("exploitable_app/proftpd/proftpd_b", "exploitable_app/proftpd/calltargets.csv"),
#    ("exploitable_app/sudo/sudo_b", "exploitable_app/opensshd/calltargets.csv"),
]

policies = [
    "",
    "vTrust",
    "IFCC",
    "IFCCSafe",
    "TypeArmor"
]

payload = "esl_scripts/testsuite_coop/shell.esl"

if __name__ == '__main__':
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('autocoop.esl_lib.gadgets').setLevel(logging.INFO)
    logging.getLogger('autocoop.exploit_generator').setLevel(logging.INFO)
    logging.getLogger("autocoop.candidate_finder").setLevel(logging.INFO)
    logging.getLogger("autocoop.esl_lib.mainloop").setLevel(logging.INFO)
    logging.getLogger("autocoop.esl_lib.loopless").setLevel(logging.INFO)
    result = [["binary"] + policies]
    for target_binary, calltargets in target_binaries:
        curr = []
        for policy in policies:
            config = exploit_generator.Config(target_binary,
                                              0x7ffff58d8000,
                                              0xa0000000,
                                              4096,
                                              gadget_csv=calltargets,
                                              policy=policy
                                              )

            explgen = exploit_generator.ExploitGenerator(config)
            print "Evaluating", policy
            tmp = test_one_payload(payload, target_binary)
            curr.append(tmp)
        result.append(curr)
        pprint.pprint(result)
    with open("results/overall.csv", "w") as csvfile:
        writer = csv.writer(csvfile)
        for row in result:
            writer.writerow(row)
    pprint.pprint(result)
    # df = pd.DataFrame(result, columns=["payload", "time_needed", "result"])
    # df.set_index("payload")
    # print df
    # df.to_csv("results/"+target_binary.split("/")[-1]+"/result_"+target_binary.split("/")[-1]+".csv")
