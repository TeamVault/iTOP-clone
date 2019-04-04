""" Generate usable objects from an esl payload definition.

.. moduleauthor:: Richard Viehoever <richard.viehoever@gmail.com>

"""

from autocoop.esl.antlr.eslLexer import eslLexer
from autocoop.esl.antlr.eslParser import eslParser
from autocoop.esl.antlr.eslListener import eslListener
from antlr4 import FileStream, CommonTokenStream, ParseTreeWalker
from importlib import import_module
import sys
import os
from collections import defaultdict

# Add esl standard library to the path
sys.path.append(os.path.abspath(os.path.dirname(__file__)+"/../esl_lib/"))

class Variable(object):
    """
    Represents a variable.

    :param value: value of the Variable
    :type value: str or int or None
    :param is_ptr: is Variable a pointer?
    :type is_ptr: bool
    """
    def __init__(self, name, value, is_ptr):
        self.name = name
        self.value = value
        self.is_ptr = is_ptr

    def __eq__(self, other):
        """
        Check whether two variable's contents are the same.

        :param other: Variable to compare to
        :type other: Variable
        :return: are both Variables equivalent?
        :rtype: bool
        """
        if self.is_ptr == other.is_ptr and self.value == other.value:
            return True
        return False

    def as_ptr(self):
        """
        Return copy of Variable as pointer.

        :return: pointer Variable
        :rtype: Variable
        """
        return Variable(self.name, self.value, True)

    def as_literal(self):
        """
        Return Copy of Variable as literal.

        :return: literal Variable
        :rtype: Variable
        """
        return Variable(self.name, self.value, False)

    def __repr__(self):
        """
        Nicer representation of Variable.

        :return: representation of Variable
        :rtype: str
        """
        return "<{} = {} ({})>".format(self.name, self.value, "ptr" if self.is_ptr else "literal")

    def copy(self):
        return Variable(self.name, self.value, self.is_ptr)


class Function(object):
    """
    Represents a function (gadget type).

    :param name: name of function
    :type name: str
    :param str script: script that defines the function and generates the object
    """
    def __init__(self, name, script):
        self.name = name
        self.script_name = script
        self.script = self.import_script(script)

    def __repr__(self):
        """
        Nicer representation of Function.

        :return: representation of Function
        :rtype: str
        """
        return "<{} {}>".format(self.name, self.script)

    def import_script(self, script):
        """
        Imports a script that contains the gadget definitions.

        First, an import from the working directory is tried, then from the standard library.

        :param str script: python script containing the definitions for the gadget
        :return: the loaded module
        :rtype: module
        """
        assert script.endswith(".py")
        return import_module(script[:-3]).gadget

    def function_id(self):
        """
        Generate an ID for the function

        :return: ID for function
        """
        val = hash(self.name)
        return val

class Gadget(object):
    """
    Represents a full gadget with its args.

    :param function: gadget type
    :type function: Function
    :param list[Variable] args: arguments to use gadget with
    """

    def __init__(self, function, args, label):
        self.function = function
        self.args = args
        self.assignments = []
        self.postconditions = []
        self.label = label
        self.next_label = None
        self.condition = None
        self.conditional_label = None

    def copy(self):
        g = Gadget(self.function, [], self.label)
        for arg in self.args:
            g.args.append(arg.copy())
        g.assignments = []
        for arg in self.assignments:
            g.assignments.append(arg.copy())
        g.postconditions = [x for x in self.postconditions]
        g.next_label = self.next_label
        g.condition = self.condition
        g.label = self.label
        g.conditional_label = self.conditional_label
        return g

    def __repr__(self):
        """
        Nicer representation of Gadget.

        :return: representation of Gadget
        :rtype: str
        """
        return "{} {}".format(self.function, "\t".join(map(str, self.args)))

    def gadget_id(self, fn):
        """
        Generate an ID for the gadget that encodes function, registers used, and arguments

        :return: ID for gadget
        """
        val = hash(fn.name)
        done = set()
        for arg in self.assignments[::-1]:
            if arg.name not in done and arg.name.startswith("_r") and arg.value == None:
                val = hash(val + hash(arg.name) + 1)
                done.add(arg.name)
        for arg in self.args[::-1]:
            if arg.name not in done and arg.name.startswith("_r"):
                val = hash(val + hash(arg.name) + 2)
                done.add(arg.name)
            elif arg.name not in done:
                val = hash(val + hash(arg.name) + 3)
                done.add(arg.name)
        for arg in self.postconditions:
            for operand in arg:
                if arg not in done and callable(getattr(operand, "startswith", None)) and operand.startswith("_r"):
                    val = hash(val + hash(operand) + 4)
                    done.add(arg)
        if self.condition:
            for operand in self.condition:
                if callable(getattr(operand, "startswith", None)) and operand.startswith("_r"):
                    val = hash(val + hash(operand) + 5)
                if operand in ("==", "<", ">"):
                    val = hash(val + hash(operand) + 6)
        return val

    def add_argument(self, argument):
        """
        Adds an argument to the gadget's argument list.

        :param Variable argument: argument to be added
        """
        self.args.append(argument)

    def concretize_assignments(self, assignments):
        for i, assignment in enumerate(self.assignments):
            if assignment.value == None:
                for assignment_known in assignments[::-1]:
                    if assignment_known.name == assignment.name:
                        self.assignments[i] = assignment_known.copy()
                        self.assignments[i].value = assignment_known.value
        for assignment in assignments[::-1]:
            for assignment2 in self.assignments:
                if assignment.name == assignment2.name:
                    break
            else:
                self.assignments.append(assignment.copy())


    def concretize_values(self):
        """
        Updates undefined values based on program state
        """
        for i, arg in enumerate(self.args):
            if arg.value == None:
                for assignment in self.assignments[::-1]:
                    if assignment.name == arg.name:
                        self.args[i] = assignment.copy()



    def update_reg_assignments(self, assignments):
        for assignment in assignments:
            if assignment.name.startswith("_r"):
                self.assignments.append(assignment)


class StatementParser(eslListener):
    """
    Parses a statement list

    :param str name: Name of the statement list
    :param list assignments: List of initial variable assignments
    :param defaultdict function: List of initial python function definitions
    :param defaultdict definitions: List of initial esl function definitions
    :param list calls: Initial list of calls
    :param list labels: Initial list of labels
    :param str or None current_label: Current active label
    """
    def __init__(self, name, assignments, functions, definitions, calls, labels, current_label):
        super(StatementParser, self).__init__()

        self.name = name
        self.assignments = assignments
        self.functions = functions
        self.definitions = definitions
        self.calls = calls
        self.labels = labels
        self.current_label = current_label

    def enterAssignment(self, ctx):
        """
        Parses assignments.

        :param eslParser.AssignmentContext ctx: Context in tree
        """
        type_hint = ctx.TYPE().getText()
        name = ctx.ARG_ID().getText()
        if type_hint == "string":
            self.add_variable(name, ctx.STRING().getText()[1:-1].decode("string_escape"))
        elif type_hint == "int":
            integer_as_str = ctx.INT().getText()
            if integer_as_str.lower().startswith("0x"):
                integer = int(integer_as_str, 16)
            else:
                integer = int(integer_as_str)
            self.add_variable(name, integer)
        else:
            raise NotImplementedError("Unknown type: " + str(type_hint))

    def enterGadget(self, ctx):
        """
        Parses gadget calls.

        :param eslParser.GadgetContext ctx: Context in tree
        """
        function = self.get_function(ctx.GADGET_ID().getText())
        gadget = Gadget(function, [], self.current_label)
        if ctx.arguments():
            for argument in ctx.arguments().argument():
                if argument.ARG_ID():
                    is_pointer = argument.getChild(0).getText() == "&"
                    name = argument.ARG_ID().getText()
                    variable = self.get_variable(name)
                else:
                    is_pointer = argument.getChild(0).getText() == "&"
                    name = argument.REG_ID().getText()
                    variable = self.get_variable(name)
                gadget.add_argument(variable.as_ptr() if is_pointer else variable.as_literal())
        self.calls.append(gadget)
        self.current_label = None

    def enterReg_assign(self, ctx):
        """
        Parses an assignment to a register.

        :param eslParser.Reg_assignContext ctx: Context in tree
        """
        assignment_target = ctx.REG_ID().getText()
        function = self.get_function(ctx.GADGET_ID().getText())
        gadget = Gadget(function, [], self.current_label)
        if ctx.arguments():
            for argument in ctx.arguments().argument():
                if argument.ARG_ID():
                    is_pointer = argument.getChild(0).getText() == "&"
                    name = argument.ARG_ID().getText()
                    variable = self.get_variable(name)
                else:
                    is_pointer = argument.getChild(0).getText() == "&"
                    name = argument.REG_ID().getText()
                    variable = self.get_variable(name)
                gadget.add_argument(variable.as_ptr() if is_pointer else variable.as_literal())
        gadget.assignments.append(Variable(assignment_target, None, False))
        self.calls.append(gadget)
        self.current_label = None

    def enterAssert_stmt(self, ctx):
        """
        Parses an assert statement.

        :param eslParser.AssertContext ctx: Context in tree
        """
        reg = ctx.getChild(1).getText()
        cmpop = ctx.CMP_OP().getText()
        value = ctx.getChild(3).getText()
        if value.lower()[0] in "0123456789":
            if value.lower().startswith('0x'):
                value = int(value, 16)
            else:
                value = int(value)
        elif value.startswith("_"):
            pass
        elif value.startswith('"'):
            value = value[1:-1].decode("string_escape")
        self.calls[-1].postconditions.append((reg, cmpop, value))

    def enterLabel_stmt(self, ctx):
        """
        Parses a label.

        :param eslParser.LabelContext ctx: Context in tree
        """
        label = ctx.LABEL_ID().getText()
        if label in self.labels or self.current_label != None:
            raise Exception("Label {} invalid (defined twice or multiple labels for same position).".format(label))
        self.labels.append(label)
        self.current_label = label

    def enterJmp_stmt(self, ctx):
        """
        Parses a jump.

        :param eslParser.JumpContext ctx: Context in tree
        """
        label = ctx.LABEL_ID().getText()
        self.calls[-1].next_label = label

    def enterIf_stmt(self, ctx):
        """
        Parses an IF.

        :param eslParser.IfContext ctx: Context in tree
        """
        reg = ctx.getChild(1).getText()
        cmpop = ctx.getChild(2).getText()
        value = ctx.getChild(3).getText()
        if value.lower().startswith("0x"):
            value = int(value, 16)
        else:
            value = int(value)
        goto = ctx.getChild(5).getText()
        if_fn = self.get_function("IF_FN")
        gadget = Gadget(if_fn, [], self.current_label)
        gadget.conditional_label = goto
        gadget.condition = (reg, cmpop, value)
        self.calls.append(gadget)
        self.current_label = None


    def get_variable(self, name):
        """
        Gets the Variable object based on the name.

        :param str name: the Variable's name
        :return: the desired Variable
        :rtype: Variable
        :raises: NameError
        """
        if name.startswith("_r"):
            return Variable(name, None, False)
        for assignment in self.assignments:
            if name == assignment.name:
                return assignment.copy()
        else:
            raise NameError("Varible {} is unknown".format(name))


    def add_variable(self, name, contents):
        """
        Adds or updates a Variable in the variables list.

        :param str name: identifier of the Variable
        :param str or int contents: value of the Variable
        :return: Variable with requested name and value
        :rtype: Variable
        """
        try:
            assignment = self.get_variable(name)
            assignment.value = contents
        except NameError:
            assignment = Variable(name, contents, False)
            self.assignments.append(assignment)
        return assignment

    def get_function(self, name):
        """
        Gets the Function object based on name.

        :param name: the Function's name
        :return: the desirerd Function
        :rtype: Function
        :raises: NameError
        """
        if name in self.functions:
            return self.functions[name]
        if name in self.definitions:
            return self.definitions[name]
        else:
            raise NameError("Function {} is unknown".format(name))


class Parser(eslListener):
    """
    Walks the program and generates the required objects.

    The Parser walks through the tree generated by antlr4 to find and generate the assignments, functions, and the order
    of calls for use in the exploit builder.

    >>> p = Parser(esl)
    >>> print p.calls
    [<EXECUTE> <system = 140737346069392 (literal)>	<ps = /bin/ps (ptr)>, <EXECUTE> <system = 140737346069392 (literal)>	<shell = /bin/sh (ptr)>]

    .. warning:: Changing the underlying antlr grammar will not break the Parser, but new features can cause exceptions\
    if the parser is not updated. Old .esl files will still be read correctly.

    :param str target_file: program to load
    """
    def __init__(self, target_file, functions=None, definitions=None):
        super(Parser, self).__init__()

        self.main_gadget = None
        if functions:
            self.functions = functions
        else:
            self.functions = defaultdict(list)
        if definitions:
            self.definitions = definitions
        else:
            self.definitions = defaultdict(list)
        self.main_calls = None

        input_stream = FileStream(target_file)
        lexer = eslLexer(input_stream)
        ctstream = CommonTokenStream(lexer)
        parser = eslParser(ctstream)
        tree = parser.esl()
        walker = ParseTreeWalker()
        walker.walk(self, tree)

    def enterEsl_import(self, ctx):
        """
        Parses an esl script import

        :param eslParser.Esl_importContext ctx: Context in tree
        """
        filename = ctx.STRING().getText()[1:-1].decode("string_escape")
        parser = Parser(filename, self.functions, self.definitions)
        for k,v in parser.functions.items():
            for val in v:
                if val not in self.functions[k]:
                    self.functions[k].append(val)
        for k,v in parser.definitions.items():
            for val in v:
                if val not in self.definitions[k]:
                    self.definitions[k].append(val)


    def enterMain(self, ctx):
        """
        Parses the mainloop (object dispatch loop)

        :param eslParser.MainContext ctx: Context in tree
        """
        self.main_gadget = self.get_function(ctx.GADGET_ID().getText())
        mainparser = StatementParser("main", [], self.functions, self.definitions, [], [], None)
        walker = ParseTreeWalker()
        walker.walk(mainparser, ctx)
        self.main_calls = mainparser

    def enterDefinition(self, ctx):
        """
        Parses a function definition

        :param eslParser.DefinitionContext ctx: Context in tree
        """
        name = ctx.GADGET_ID().getText()
        arguments = []
        if ctx.arg_ids():
            for argument in ctx.arg_ids().ARG_ID():
                arguments.append(Variable(argument.getText(), None, False))
        defparser = StatementParser(name, arguments, self.functions, self.definitions, [], [], None)
        walker = ParseTreeWalker()
        walker.walk(defparser, ctx)
        self.definitions[name].append(defparser)


    def enterPy_import(self, ctx):
        """
        Parses a python import for a function

        :param eslParser.Py_importContext ctx: Context in tree
        """
        name = ctx.GADGET_ID().getText()
        script = ctx.STRING().getText()[1:-1].decode("string_escape")
        self.add_function(name, script)


    def get_function(self, name):
        """
        Gets the Function object based on name.

        :param name: the Function's name
        :return: the desirerd Function
        :rtype: Function
        :raises: NameError
        """
        if name in self.functions:
            return self.functions[name]
        else:
            raise NameError("Function {} is unknown".format(name))

    def add_function(self, name, script):
        """
        Adds or updates a function.

        :param str name: name of the function
        :return: Function with requested name
        :rtype: Function
        """
        function = Function(name, script)
        self.functions[name].append(function)
        return function


if __name__ == "__main__":
    p = Parser("../../esl_scripts/exploit_demo.esl")
    print p.calls
