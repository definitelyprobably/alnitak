
import os
import re

from alnitak import prog as Prog


def read(prog):
    """
    Calls:
        - NONE
    """
    prog.log.info1("+++ reading datafile '{}'".format(prog.datafile))
    retval = Prog.RetVal.ok

    try:
        with open(str(prog.datafile), "r") as file:
            raw = file.read().splitlines()
    except FileNotFoundError as ex:
        # if there is no datafile, then posthook has nothing to do: we should
        # just exit.
        prog.log.info1("  + no file to read")
        return Prog.RetVal.exit_ok
    except OSError as ex:
        prog.log.error(
                "datafile '{}': {}".format(ex.filename, ex.strerror.lower()))
        return Prog.RetVal.exit_failure


    line_pos = 0

    for l in raw:
        line_pos += 1

        # matches empty line
        match = re.match(r'^\s*(#.*)?$', l)
        if match:
            continue

        # prehook line
        #   domain  dane_cert  live_cert  archive_cert  pending
        match = re.match(r'(?P<domain>{})\s+"(?P<dane>(\\.|[^"])+)"\s+"(?P<live>(\\.|[^"])+)"\s+"(?P<archive>(\\.|[^"])+)"\s+(?P<pending>(0|1))'.format(prog.tlsa_domain_regex), l)
        if match:

            prog.log.info3("  + line {}: prehook line (pending: {})".format(
                                            line_pos, match.group('pending')))

            prog.data.add_line( prog, Prog.DataPre( match.group('domain'),
                                               line_pos,
                                               match.group('dane'),
                                               match.group('live'),
                                               match.group('archive'),
                                               match.group('pending') ) )

            continue

        # posthook line
        #   x.com 301 25 tcp x.com unix_time 0 hash
        match = re.match(r'(?P<domain>{})\s+(?P<tlsa_spec>{})\s+(?P<tlsa_port>[0-9]+)\s+(?P<tlsa_protocol>{})\s+(?P<tlsa_domain>{})\s+(?P<time>[0-9]+)\s+(?P<pending>(0|1))\s+(?P<hash>[a-fA-F0-9]+)'.format(prog.tlsa_domain_regex, prog.tlsa_parameters_regex, prog.tlsa_protocol_regex, prog.tlsa_domain_regex), l)
        if match:

            prog.log.info3("  + line {}: posthook line (pending: {})".format(
                                            line_pos, match.group('pending')))

            prog.data.add_line( prog, Prog.DataPost( match.group('domain'),
                                                line_pos,
                                                Prog.Tlsa(
                                                  match.group('tlsa_spec'),
                                                  match.group('tlsa_port'),
                                                  match.group('tlsa_protocol'),
                                                  match.group('tlsa_domain') ),
                                                match.group('pending'),
                                                match.group('time'),
                                                match.group('hash') ) )

            continue

        # delete line
        #   x.com delete 301 25 tcp x.com unix_time count hash
        match = re.match(r'(?P<domain>{})\s+delete\s+(?P<tlsa_spec>{})\s+(?P<tlsa_port>[0-9]+)\s+(?P<tlsa_protocol>{})\s+(?P<tlsa_domain>{})\s+(?P<time>[0-9]+)\s+(?P<count>[0-9]+)\s+(?P<hash>[a-fA-F0-9]+)'.format(prog.tlsa_domain_regex, prog.tlsa_parameters_regex, prog.tlsa_protocol_regex, prog.tlsa_domain_regex), l)
        if match:

            prog.log.info3("  + line {}: delete line (count: {})".format(
                                            line_pos, match.group('count')))

            prog.data.add_line( prog, Prog.DataDelete(
                                            match.group('domain'),
                                            line_pos,
                                            Prog.Tlsa( match.group('tlsa_spec'),
                                                  match.group('tlsa_port'),
                                                  match.group('tlsa_protocol'),
                                                  match.group('tlsa_domain') ),
                                            match.group('count'),
                                            match.group('time'),
                                            match.group('hash') ) )

            continue

        prog.log.error("line {}: malformed line".format(line_pos))
        retval = Prog.RetVal.exit_failure

    prog.log.info3(prog.data)
    return retval


def check_data(prog):
    """
    Calls:
        - NONE
    """
    prog.log.info3("+++ checking datafile data")
    retval = Prog.RetVal.ok
    # given the prog.data object, which was set by the 'read_datafile'
    # function, check the data in the file.

    # - for every posthook line in a group, there MUST be a prehook line
    #   with (chain.pem|fullchain.pem) if the param is DANE-TA(2) or
    #   (cert.pem|fullchain.pem) if the param is DANE-EE(3).
    # - if there is a posthook line, every prehook line in the group must have
    #   pending set to '1'.
    # - if there are no posthook lines, every prehook line in the group must
    #   have pending set to '0'.
    for g in prog.data.groups:
        if g.post:
            file_list = []
            for l in g.pre:
                file_list += [ l.cert.live.name ]
                if not l.pending == '1':
                    prog.log.error("line {}: pending state on prehook line for domain '{}' conflicts with posthook entry at line {}".format(l.lineno, l.domain, g.post[0].lineno))
                    retval = Prog.RetVal.exit_failure
            for l in g.post:
                if l.tlsa.usage == '2':
                    if not ('chain.pem' in file_list or
                                                'fullchain.pem' in file_list):
                        prog.log.error("line {}: posthook line with tlsa usage '2' has no prehook line with an appropriate certificate to use".format(l.lineno))
                        retval = Prog.RetVal.exit_failure
                else:
                    if not ('cert.pem' in file_list or
                                                'fullchain.pem' in file_list):
                        prog.log.error("line {}: posthook line with tlsa usage '3' has no prehook line with an appropriate certificate to use".format(l.lineno))
                        retval = Prog.RetVal.exit_failure
        else:
            for l in g.pre:
                if not l.pending == '0':
                    prog.log.error("line {}: orphaned prehook line: domain '{}' has no posthook (tlsa) line".format(l.lineno, l.domain))
                    retval = Prog.RetVal.exit_failure

    if retval == Prog.RetVal.ok:
        prog.log.info3("  + datafile ok")

    return retval


def write_prehook(prog):
    """
    Calls:
        - NONE
    """
    prog.log.info1(
            "+++ writing datafile (prehook): '{}'".format(prog.datafile))

    data = ""

    for t in prog.target_list:
        for c in t.certs:
            prog.log.info3("  + {}\n{}".format(t.domain, c))
            data += '{} "{}" "{}" "{}" 0\n'.format(
                                        t.domain, c.dane, c.live, c.archive)

    if not data:
        prog.log.info1("  + no dane symlinks changed: nothing to write")
        return Prog.RetVal.ok

    header = "# {0} {1}\n# prehook mode {2}, {2:%s}\n".format(
                                        prog.name, prog.version, prog.timenow)


    try:
        with open(str(prog.datafile), "a") as file:
            file.write(header)
    except OSError as ex:
        prog.log.error("writing datafile '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return Prog.RetVal.exit_failure

    if fix_permissions(prog):
        return Prog.RetVal.exit_failure

    try:
        with open(str(prog.datafile), "a") as file:
            file.write(data)
    except OSError as ex:
        prog.log.error("writing datafile '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return Prog.RetVal.exit_failure

    return Prog.RetVal.ok


def write_posthook(prog):
    """
    Calls:
        - remove
    """
    prog.log.info1("+++ writing to datafile '{}'".format(prog.datafile))
    data = ""

    for group in prog.data.groups:
        for l in group.pre:
            prog.log.info3(" ++ writing prehook datafile lines...")
            prog.log.info3("{}".format(l))
            if l.state == Prog.DataLineState.write:
                data += '{} "{}" "{}" "{}" {}\n'.format(
                        l.domain, l.cert.dane, l.cert.live, l.cert.archive,
                        l.pending)
        for l in group.post:
            prog.log.info3(" ++ writing posthook datafile lines...")
            prog.log.info3("{}".format(l))
            if l.state == Prog.DataLineState.write:
                data += "{} {}{}{} {} {} {} {} {} {}\n".format(
                        l.domain, l.tlsa.usage, l.tlsa.selector,
                        l.tlsa.matching, l.tlsa.port, l.tlsa.protocol,
                        l.tlsa.domain, l.time, l.pending, l.hash)
        for l in group.special:
            prog.log.info3(" ++ writing delete datafile lines...")
            prog.log.info3("{}".format(l))
            if l.state == Prog.DataLineState.write:
                data += "{} delete {}{}{} {} {} {} {} {} {}\n".format(
                        l.domain, l.tlsa.usage, l.tlsa.selector,
                        l.tlsa.matching, l.tlsa.port, l.tlsa.protocol,
                        l.tlsa.domain, l.time, l.count, l.hash)

    if not data:
        prog.log.info1("  + no data to write")
        return remove(prog)

    header = "# {0} {1}\n# posthook mode {2}, {2:%s}\n".format(
                                        prog.name, prog.version, prog.timenow)

    try:
        with open(str(prog.datafile), "w") as file:
            file.write(header)
    except OSError as ex:
        prog.log.error("writing datafile '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return Prog.RetVal.exit_failure

    if fix_permissions(prog):
        return Prog.RetVal.exit_failure

    try:
        with open(str(prog.datafile), "a") as file:
            file.write(data)
    except OSError as ex:
        prog.log.error("writing datafile '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return Prog.RetVal.exit_failure

    return Prog.RetVal.ok


def remove(prog):
    """
    Calls:
        - NONE
    """
    prog.log.info1("+++ removing datafile '{}'".format(prog.datafile))
    try:
        prog.datafile.unlink()
    except FileNotFoundError as ex:
        pass
    except OSError as ex:
        prog.log.error("removing datafile '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        retval = True
        return Prog.RetVal.exit_failure

    return Prog.RetVal.ok


def fix_permissions(prog):
    """
    Calls:
        - None
    """
    prog.log.info3(" ++ checking/fixing mode of datafile: should be '0600'")
    try:
        prog.datafile.chmod(0o600)
    except OSError as ex:
        prog.log.error(
            "changing permissions of datafile '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return True

    prog.log.info3(
            " ++ checking/fixing owner of datafile: should be 'root:root'")
    try:
        if not prog.testing_mode:
            os.chown(str(prog.datafile), 0, 0)
    except OSError as ex:
        prog.log.error(
                "changing owner of datafile '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return True

    return False


