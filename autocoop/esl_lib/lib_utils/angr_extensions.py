import angr

class ResolveSingleAddress(angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategy):
    """
    Ensures that wildcard memory reads always resolve to a predetermined address.
    """
    def __init__(self, target, **kwargs):
        super(ResolveSingleAddress, self).__init__(**kwargs)
        self._target = target

    def _eval(self, memory, addr, n, **kwargs):
        """
        Gets n solutions for an address.
        """
        return memory.state.se.eval_upto(addr, n, exact=True, extra_constraints=[addr == self._target], **kwargs)

    def _concretize(self, memory, addr):
        memory.state.se.add(addr == self._target)
        addr = self._eval(memory, addr, 2)
        if len(addr) == 1:
            return addr