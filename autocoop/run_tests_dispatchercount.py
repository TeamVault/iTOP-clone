import autocoop.exploit_generator as exploit_generator
import logging
import csv
import time
import pprint

payload = "esl_scripts/testsuite_coop/regset.esl"

target_binaries = [
    # "exploitable_app/testapp/cmake-build-debug/libAPP.so",
 "exploitable_app/nginx/build/sbin/nginx",
 "exploitable_app/apache2/httpd", "exploitable_app/redis/redis-server",
"exploitable_app/nodejs/libnode.so",
      "exploitable_app/libtorrent/libtorrent.so",
  "exploitable_app/firefox/libxul.so",
    "exploitable_app/chromium/chrome"
]

result = [["time", "name", "LINKEDLIST", "MAINLOOP", "RECURSION"]]

if __name__ == '__main__':
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('autocoop.esl_lib.gadgets').setLevel(logging.INFO)
    logging.getLogger('autocoop.exploit_generator').setLevel(logging.INFO)
    logging.getLogger("autocoop.candidate_finder").setLevel(logging.INFO)
    logging.getLogger("autocoop.esl_lib.mainloop").setLevel(logging.INFO)
    logging.getLogger("autocoop.esl_lib.loopless").setLevel(logging.INFO)

    for target_binary in target_binaries:
        time_start = time.time()
        config = exploit_generator.Config(target_binary,
                                          0x7ffff58d8000,
                                          0xa0000000,
                                          4096,
                                          dispatcheranalysis=True)

        explgen = exploit_generator.ExploitGenerator(config)
        program = exploit_generator.Parser(payload)
        result.append([target_binary])
        for dispatcher in program.main_gadget:
            dispatchers = list(dispatcher.script[0](explgen.target_app, explgen.config, program.main_calls.calls))
            result[-1].append(len(dispatchers))
        result[-1].insert(0, time.time()-time_start)
        with open("results/dispatchers.csv", "w") as csvfile:
            writer = csv.writer(csvfile)
            for row in result:
                writer.writerow(row)
        pprint.pprint(result)
