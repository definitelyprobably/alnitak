
import re
import pwd
import shlex

from alnitak import prog as Prog



def read(prog):
    """
    Calls:
        - get_tlsa_param
        - get_api_cloudflare4
        - get_api_binary
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
                prog.target_list += [ Prog.Target(active_section.lower()) ]
                target = prog.target_list[-1]
                if default_api:
                    target.api = default_api
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
                state.add_error(prog, "malformed line")
                continue

            if param == "tlsa":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(prog, "no tlsa record given")
                elif len(inputs) == 1:
                    state.add_error(prog, "tlsa record given insufficient data")
                elif len(inputs) > 4:
                    state.add_error(prog, "tlsa record given superfluous data")
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

                if inputs[0] == "cloudflare4":
                    api = get_api_cloudflare4(prog, inputs[1:], state)
                    if api:
                        if active_section:
                            target.api = api
                        else:
                            default_api = api
                elif inputs[0] == "binary":
                    api = get_api_binary(prog, inputs[1:], state)
                    if api:
                        if active_section:
                            target.api = api
                        else:
                            default_api = api
                else:
                    state.add_error(prog, "unrecognized api scheme")

            elif param == "dane_directory":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(
                        prog, "dane_directory command given no input")
                elif len(inputs) > 1:
                    state.add_error(
                        prog, "dane_directory command given superfluous input")
                else:
                    prog.set_dane_directory(inputs[0])

            elif param == "letsencrypt_directory":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(
                        prog, "letsencrypt_directory command given no input")
                elif len(inputs) > 1:
                    state.add_error(prog,
                        "letsencrypt_directory command given superfluous input")
                else:
                    prog.set_letsencrypt_directory(inputs[0])

            elif param == "ttl":
                prog.log.info3("  + line {}: parameter: {}, inputs: {}".format(
                                                    line_pos, param, inputs))
                if len(inputs) == 0:
                    state.add_error(
                        prog, "ttl command given no input")
                elif len(inputs) > 1:
                    state.add_error(prog,
                        "ttl command given superfluous input")
                else:
                    try:
                        ttl_value = int(inputs[0])
                    except ValueError as ex:
                        state.add_error(prog, "ttl value not an integer")
                        continue

                    if ttl_value < prog.ttl_min:
                        state.add_error(prog,
                                        "ttl value less than minimum value")
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

        state.add_error(prog, "malformed line")


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

    return Prog.RetVal.ok


def get_tlsa_param(prog, input_list, active_section, state):
    """
    Calls:
        - is_input_port
        - is_input_protocol
        - is_input_domain
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
    try:
        port_num = int(inp)
        if port_num == 0 or port_num > 65535:
            return False
    except ValueError:
        return False
    tlsa.port = inp
    return True

def is_input_protocol(prog, inp, tlsa):
    if re.match(r"{}$".format(prog.tlsa_protocol_regex), inp):
        tlsa.protocol = inp
        return True
    return False

def is_input_domain(prog, inp, tlsa):
    if re.match(r'{}$'.format(prog.tlsa_domain_regex), inp):
        tlsa.domain = inp
        return True
    return False


def get_api_cloudflare4(prog, input_list, state):
    """
    Calls:
        - is_api_input_zone
        - is_api_input_email
        - is_api_input_key
        - read_cloudflare4_api_file
    """
    if len(input_list) == 0:
        state.add_error(prog, "'cloudflare4' api scheme not given any data")
        return None
    elif len(input_list) > 3:
        state.add_error(prog, "'cloudflare4' api scheme given superfluous data")
        return None
    elif len(input_list) == 2:
        state.add_error(prog, "'cloudflare4' api scheme not given enough data")
        return None
    elif len(input_list) == 1:
        inputs = read_cloudflare4_api_file(prog, input_list[0], state)
        if not inputs:
            return None
    else:
        inputs = input_list

    # MUST be zone, email and key
    api = Prog.ApiCloudlare4()
    avail_inputs = [ is_api_input_zone, is_api_input_email, is_api_input_key ]

    for inp in inputs:
        for check in avail_inputs:
            if check(prog, inp, api):
                avail_inputs.remove(check)
                break
        else:
            state.add_error(
                    prog, "'cloudflare4' api scheme given malformed data")
            return None

    return api

def read_cloudflare4_api_file(prog, file, state):
    """
    Calls:
        - None
    """
    try:
        with open(str(file), "r") as f:
            raw = f.read().splitlines()
    except FileNotFoundError as ex:
        prog.log.error(
                "cloudflare4 API file '{}' not found".format(ex.filename))
        return None
    except OSError as ex:
        prog.log.error(
                "reading cloudflare4 API file '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return None

    errors = False
    ret = []
    linepos = 0
    for l in raw:
        linepos += 1

        match = re.match(r'^\s*(#.*)?$', l)
        if match:
            continue

        match = re.match(
                    r'\s*(?P<param>\w+)\s*=\s*(?P<input>[^#]*)(\s*|\s#.*)$', l)
        if match:
            param = match.group('param')
            try:
                inputs = shlex.split(match.group('input'))
            except ValueError:
                state.add_error(prog, "cloudflare4 API file '{}' has malformed expression on line {}".format(file, linepos))
                errors = True
                continue

            if param == "email" or param == "zone" or param == "key":
                if len(inputs) != 1:
                    state.add_error(prog, "cloudflare4 API file '{}': malformed '{}' command on line {}".format(file, param, linepos))
                    errors = True
                    continue
                ret += [ '{}:{}'.format(param, inputs[0]) ]
                continue

            state.add_error(prog, "cloudflare4 API file '{}': unrecognized command on line {}: '{}'".format(file, linepos, param))
            errors = True
            continue

        state.add_error(prog, "cloudflare4 API file '{}' has malformed expression on line {}".format(file, linepos))
        errors = True

    if errors:
        return None

    return ret

def is_api_input_zone(prog, inp, api):
    if re.match(r'zone:[a-zA-Z0-9]+$', inp):
        api.zone = inp[5:]
        return True
    return False

def is_api_input_email(prog, inp, api):
    if re.match(r'email:\S+@{}'.format(prog.tlsa_domain_regex), inp):
        api.email = inp[6:]
        return True
    return False

def is_api_input_key(prog, inp, api):
    if re.match(r'key:\w+$', inp):
        api.key = inp[4:]
        return True
    return False


def get_api_uid(prog, state, uid):
    if len(uid) == 0:
        state.add_error(prog, "'binary' api scheme: no uid input given")
        return None

    try:
        return int(uid)
    except ValueError:
        pass

    try:
        return pwd.getpwnam(uid).pw_uid
    except KeyError:
        pass

    state.add_error(prog, "'binary' api scheme: uid input '{}' not a valid input".format(uid))
    return None


def get_api_binary(prog, input_list, state):
    if input_list[0][0:4] == "uid:":
        uid = get_api_uid(prog, state, input_list[0][4:])
        if uid == None:
            return None
        comms = input_list[1:]
    else:
        uid = None
        comms = input_list

    if len(comms) == 0:
        state.add_error(prog, "'binary' api scheme given no command to run")
        return None

    return Prog.ApiBinary(comms, uid=uid)


