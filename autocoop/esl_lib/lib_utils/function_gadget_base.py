from __builtin__ import False

import autocoop.esl_lib.lib_utils.candidate_finder as candidate_finder
import autocoop.esl_lib.lib_utils.solver_utils as solver_utils
import logging
import autocoop.builder.builder as builder
import angr


class FunctionGadget(object):
    """
    Base represtation of a gadget.

    :param app: Parent angr project
    :param Config config: Config of app
    :param autocoop.esl.parser.Gadget gadget_def: IR of gadget
    :param list calltarget_list: List of valid calltargets
    """
    name = "DEFAULT"

    def __init__(self, app, config, gadget_def, calltarget_list=list()):
        self.app = app
        self.config = config
        self.gadget_def = gadget_def
        self.candidates = calltarget_list

    def get_candidates(self):
        """
        Generates a list of calltargets
        """
        self.candidates = candidate_finder.get_candidate_gadgets_from_csv(self.app, self.config.other_args["gadget_csv"])

    def setup_state(self, gadget_symbol):
        """
        Sets up the angr state

        :param gadget_symbol: Symbol of gadget
        :return: Angr state
        """
        state = self.app.factory.call_state(gadget_symbol.rebased_addr,
                                       add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                                    angr.options.INITIALIZE_ZERO_REGISTERS}, ret_addr=0xdeadbeef)
        solver_utils.ensure_preconditions(state, self.gadget_def)
        return state

    def simulate(self, state):
        """
        Simulates a state until the exit condition is met

        :param state: State to simulate
        :return: List of valid resulting states
        :rtype: list
        """
        simgr = self.app.factory.simgr(state)
        simgr.use_technique(solver_utils.CheckUniquenessAndReturn())
        simgr.run()
        if "state_return" in simgr.stashes:
            return simgr.state_return
        return []

    def add_constraints(self, state):
        """
        Adds constraints to state

        :param state: State to modify
        """
        pass

    def add_postconditions(self, state, gadget):
        """
        Adds postconditions to state

        :param state: State to modify
        :param gadget: IR of gadget
        """
        solver_utils.ensure_postconditions(state, self.gadget_def)

    def generate_object(self, state, gadget):
        """
        Generates the object to add to the builder

        :param state: State to get the object from
        :param gadget: IR of gadget
        :return: Gadget address and builder object
        """
        logging.getLogger("autocoop.esl_lib.gadgets").info("[+] Valid {} gadget found".format(self.name))
        return gadget.rebased_addr

    def valid_object(self, state, gadget):
        """
        Steps to take after a valid object is found

        :param state: State after gadget is called
        :param gadget: IR of gadget
        """
        pass

    def configure_state(self, state):
        """
        Configures the state as required by the solver

        :param state: State to check
        """
        pass

    def check_if_valid_state(self, state):
        """
        Returns true if a state is valid

        :param state: State to check
        """
        return state.satisfiable()

    def search(self):
        """
        Searches through the candidate set for valid gadgets and generates the gadget objects. This function should
        not be modified, instead modify the functions called by search.

        :yields: Gadget addresses and builder objects
        """
        if not self.candidates:
            self.get_candidates()
        candidates = self.candidates

        length = len(candidates)
        counter = 0
        to_remove = []
        for index, (vtable_addr, gadget) in enumerate([x for x in candidates]):
            counter += 1
            logging.getLogger("autocoop.esl_lib.gadgets").info(
                "[*] Evaluating potential {} gadget {}/{}: {}".format(self.name, counter, length, gadget))

            state = self.setup_state(gadget)
            self.configure_state(state)
            simulation = self.simulate(state)
            for i in self.manage_resulting_states(simulation, gadget, to_remove):
                yield i
        for i in to_remove:
            if i in self.candidates:
                self.candidates.remove(i)
        logging.getLogger("autocoop.esl_lib.gadgets").info("[-] {} search completed.".format(self.name))

    def manage_resulting_states(self, simulation, gadget, to_remove):
        yielded = False
        for resulting_state in simulation:
            self.add_constraints(resulting_state)
            self.add_postconditions(resulting_state, gadget)
            if self.check_if_valid_state(resulting_state):
                obj = self.generate_object(resulting_state, gadget)
                if obj:
                    self.valid_object(resulting_state, gadget)
                    yielded = True
                    yield obj
        if not yielded:
            if (1, gadget) in self.candidates:
                to_remove.append((1, gadget))

    @classmethod
    def filter_candidate_list(cls, app, candidates, call=None):
        """
        Further filter the candidate list based on the disassembly

        :param app: Parent angr project
        :param candidates: List of candidates to filter
        :param call: The concrete gadget
        :return:
        """
        if call:
            return [candidate for candidate in candidates if cls.is_candidate_gadget(app, candidate[1], call)]
        else:
            return [candidate for candidate in candidates if cls.is_candidate_function(app, candidate[1])]

    @classmethod
    def is_candidate_gadget(cls, app, candidate, call):
        """
        Semantic filtering based on disassembly, using information that is only known at runtime like register
        assignments.

        :param app: Parent angr project
        :param candidate: A candidate gadget
        :param call: The concrete gadget
        :return: True if gadget is valid gadget for this category
        :rtype: bool
        """
        return True

    @classmethod
    def is_candidate_function(cls, app, candidate):
        """
        Semantic filtering based on disassembly, using only the gadget category, but no information like
        register assignments or concrete variable values.

        :param app: Parent angr project
        :param candidate: A candidate gadget
        :return: True if gadget is valid gadget for this category
        :rtype: bool
        """
        return True
