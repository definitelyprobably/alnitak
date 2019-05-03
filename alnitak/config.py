
import re
import shlex
from importlib import import_module

from alnitak import prog as Prog
from alnitak import exceptions as Except


def read(prog):
    """Read a configuration file and set internal state data.

    Read a program file, set data and return error if any problem occurred.

    Args:
        prog (State): contains the config file to read, and also has member
            data that needs to be set from the contents of the config file.

    Returns:
        RetVal: RetVal.config_failure for errors in the config file,
            RetVal.exit_failure for OS failures in opening/reading the
            config file, RetVal.ok if no errors found.
    """
    try:
        with open(str(prog.config), "r") as file:
            raw = file.read().splitlines()
    except FileNotFoundError as ex:
        prog.log.error("config file '{}' not found".format(ex.filename))
        return Prog.RetVal.exit_failure
    except OSError as ex:
        prog.log.error(
                "config file '{}': {}".format(ex.filename, ex.strerror.lower()))
        return Prog.RetVal.exit_failure

    prog.log.info1("+++ reading config file '{}'".format(prog.config))

    line_pos = 0
    state = Prog.ConfigState()

    active_section = None
    target = None

    default_tlsa_list = []
    default_api = None

    log_level = None

    for l in raw:
        line_pos += 1
        state.line(line_pos)

        # matches section: "[DOMAIN]"
        match = re.match(r'\s*\[\s*(?P<section>((\w[a-zA-Z0-9-]*\w|\w+)\.)+\w+)\s*\](\s*|\s+#.*)$', l)
        if match:
            active_section = match.group('section').lower()
            prog.log.info3("  + line {}: section: {}".format(
                                                    line_pos, active_section))
            for t in prog.target_list:
                if t.matches_domain(active_section):
                    target = t
                    break
            else:
                prog.target_list += [ Prog.Target(active_section) ]
                target = prog.target_list[-1]
                if default_api:
                    target.api = default_api.copy()
                    # NOT 'target.api = default_api'. If we do that, then in
                    # the following line when we change the api object's
                    # domain attribute, it will change the domain in _all_ of
                    # the targets. We need to create a NEW object that is
                    # (mostly) the same as the default_api object, and we do
                    # this with the 'copy' method.
                    target.api.domain = active_section
                for tlsa in default_tlsa_list:
                    tlsa.domain = active_section
                    target.add_tlsa(tlsa)
            continue

        # matches parameter: "param = input"
        match = re.match(
                    r'\s*(?P<param>\w+)\s*=\s*(?P<input>[^#]*)(\s*|\s#.*)$', l)
        if match:
            param = match.group('param')
            try:
                inputs = shlex.split(match.group('input'))
            except ValueError:
                if len(l) > 23:
                    state.add_error(prog,
                            "unrecognized command: '{}...'".format(l[:20]))
                else:
                    state.add_error(prog,
                            "unrecognized command: '{}'".format(l))
                continue

            if param == "tlsa":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(prog, "no tlsa data given")
                elif len(inputs) == 1:
                    state.add_error(prog, "tlsa record given insufficient data")
                elif len(inputs) > 4:
                    state.add_error(prog, "tlsa record given superfluous data: '{}'".format(' '.join(inputs[4:])))
                else:
                    tlsa = get_tlsa_param(prog, inputs, active_section, state)
                    if tlsa:
                        if active_section:
                            target.add_tlsa(tlsa)
                        else:
                            default_tlsa_list += [ tlsa ]

            elif param == "api":
                prog.log.info3(
                        "  + line {}: parameter: {}, inputs: ({})...".format(
                                                line_pos, param, len(inputs) ))
                if len(inputs) == 0:
                    state.add_error(prog, "api command given no input")
                    continue

                if inputs[0] in prog.apis:
                    apimod = import_module('alnitak.api.' + inputs[0])
                    api = apimod.get_api(prog, active_section,
                                         inputs[1:], state)
                    if api:
                        if active_section:
                            target.api = api
                        else:
                            default_api = api
                else:
                    state.add_error(prog,
                            "unrecognized api scheme: '{}'".format(inputs[0]))

            elif param == "dane_directory":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(
                        prog, "dane_directory command given no input")
                elif len(inputs) > 1:
                    state.add_error(prog, "dane_directory command given superfluous input: '{}'".format(' '.join(inputs[1:])))
                else:
                    prog.set_dane_directory(inputs[0])

            elif param == "letsencrypt_directory":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(
                        prog, "letsencrypt_directory command given no input")
                elif len(inputs) > 1:
                    state.add_error(prog, "letsencrypt_directory command given superfluous input: '{}'".format(' '.join(inputs[1:])))
                else:
                    prog.set_letsencrypt_directory(inputs[0])

            elif param == "log_level":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(
                        prog, "log_level command given no input")
                elif len(inputs) > 1:
                    state.add_error(prog, "log_level command given superfluous input: '{}'".format(' '.join(inputs[1:])))
                else:
                    if inputs[0] not in [ 'no', 'normal', 'verbose', 'debug' ]:
                        state.add_error(prog, "")
                        continue

                    log_level = inputs[0]

            elif param == "ttl":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(
                        prog, "ttl command given no input")
                elif len(inputs) > 1:
                    state.add_error(prog, "ttl command given superfluous input: '{}'".format(' '.join(inputs[1:])))
                else:
                    try:
                        import alnitak.parser
                        # python 3.4: 'from alnitak import parser' will
                        # cause an error because of circular imports.
                        # Importing like this will work
                        ttl_value = alnitak.parser.ttl_check(prog, 0, 'config', inputs[0])
                    except Except.Error1013:
                        state.add_error(prog, "ttl value '{}' not an integer".format(inputs[0]))
                        continue
                    except Except.Error1100 as ex:
                        state.add_error(prog, "ttl value '{}' exceeds maximum value of '{}'".format(inputs[0], ex.max))
                        continue
                    except Except.Error1101 as ex:
                        state.add_error(prog, "ttl value '{}' less than minimum value of '{}'".format(inputs[0], ex.min))
                        continue

                    prog.set_ttl(ttl_value)


            else:
                state.add_error(prog,
                                "unrecognized parameter '{}'".format(param))

            continue

        # matches empty line
        match = re.match(r'^\s*(#.*)?$', l)
        if match:
            continue

        if len(l) > 23:
            state.add_error(prog,
                    "unrecognized command: '{}...'".format(l[:20]))
        else:
            state.add_error(prog, "unrecognized command: '{}'".format(l))


    state.lineno = None
    for t in prog.target_list:
        if not t.tlsa:
            state.add_error(
                    prog, "target '{}' has no tlsa record".format(t.domain))
        if not t.api:
            state.add_error(
                    prog, "target '{}' has no api scheme".format(t.domain))

    if state.errors:
        return Prog.RetVal.config_failure

    prog.log.info3("+++ targets...")
    if prog.target_list:
        for t in prog.target_list:
            prog.log.info3(str(t))
    else:
        prog.log.info3("  + no targets found")
        prog.log.error("config file: no targets given")
        return Prog.RetVal.config_failure

    # set the delayed log level. We don't do this straight away or else we
    # will have mixed logging for this function itself.
    if log_level:
        prog.set_log_level(log_level)

    return Prog.RetVal.ok


def get_tlsa_param(prog, input_list, active_section, state):
    """Create a Tlsa object from a config file line.

    Given a 'tlsa = ...' line in a config file, construct and return a
    Tlsa object, or else 'None' if an error is encountered.

    Args:
        prog (State): not changed.
        input_list (list(str)): a list of whitespace-delimited strings
            corresponding to the inputs following 'tlsa =' (i.e., the
            'inputs' of the 'tlsa' parameter).
        active_section (str): set to the section the 'tlsa' parameter is
            in, or else 'None' if given outside of any section.
        state (ConfigState): class to record config file errors.

    Returns:
        Tlsa: creates a Tlsa object from the arguments.
        None: if an error is encountered.
    """
    param = input_list[0]
    if not re.match(r'{}$'.format(prog.tlsa_parameters_regex), param):
        state.add_error(prog, "tlsa record: parameters not recognized")
        return None

    available_inputs = [ is_input_port, is_input_protocol, is_input_domain ]

    tlsa = Prog.Tlsa(param, None, "tcp", active_section)

    for inp in input_list[1:]:
        for check in available_inputs:
            if check(prog, inp, tlsa):
                available_inputs.remove(check)
                break
        else:
            state.add_error(prog, "tlsa record: malformed data")
            return None

    if not tlsa.port:
        state.add_error(prog, "tlsa record: port not specified")
        return None

    return tlsa

def is_input_port(prog, inp, tlsa):
    """Set the Tlsa object's port data if the input is 'port-like'.

    Args:
        prog (State): not changed.
        inp (str): the input to check if it is a port number.
        tlsa (Tlsa): the Tlsa object to set with the port number if 'inp'
            is an integer.

    Returns:
        bool: 'True' if the port data in 'tlsa' was set to 'inp', 'False'
            if not.
    """
    try:
        port_num = int(inp)
        if port_num == 0 or port_num > 65535:
            return False
    except ValueError:
        return False
    tlsa.port = inp
    return True

def is_input_protocol(prog, inp, tlsa):
    """Set the Tlsa object's protocol data if the input is 'protocol-like'.

    Args:
        prog (State): not changed.
        inp (str): the input to check if it is a protocol.
        tlsa (Tlsa): the Tlsa object to set with the protocol if 'inp'
            matches a regex to test protocols against.

    Returns:
        bool: 'True' if the protocol data in 'tlsa' was set to 'inp',
            'False' if not.
    """
    if re.match(r"{}$".format(prog.tlsa_protocol_regex), inp):
        tlsa.protocol = inp
        return True
    return False

def is_input_domain(prog, inp, tlsa):
    """Set the Tlsa object's domain data if the input is 'domain-like'.

    Args:
        prog (State): not changed.
        inp (str): the input to check if it is a protocol.
        tlsa (Tlsa): the Tlsa object to set with the protocol if 'inp'
            matches a regex to test domains against.

    Returns:
        bool: 'True' if the domain data in 'tlsa' was set to 'inp',
            'False' if not.
    """
    if re.match(r'{}$'.format(prog.tlsa_domain_regex), inp):
        tlsa.domain = inp
        return True
    return False

