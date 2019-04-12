
import os
import re
import argparse
import pathlib

from alnitak import prog as Prog
from alnitak import exceptions as Except
from alnitak import certop


def arg_type(inp):
    """Function to call in argparse when checking inputs to the '--print' flag.

    Args:
        inp (str): input string from the command-line parser.

    Returns:
        Record: object containing the tlsa parameters and certificate/domain
            extracted from the input.

    Raises:
        argparse.ArgumentTypeError: if input does not conform.
    """
    if len(inp) < 5:
        raise argparse.ArgumentTypeError("malformed input '{}': must be like 'XYZ:CERT'.".format(inp))
    if inp[0] not in ['2', '3']:
        raise argparse.ArgumentTypeError("usage value '{}' not recognized.".format(inp[0]))
    if inp[1] not in ['0', '1']:
        raise argparse.ArgumentTypeError("selector value '{}' not recognized.".format(inp[1]))
    if inp[2] not in ['0', '1', '2']:
        raise argparse.ArgumentTypeError("matching type value '{}' not recognized.".format(inp[2]))
    if inp[3] != ':':
        raise argparse.ArgumentTypeError("malformed input '{}': must be like 'XYZ:CERT'.".format(inp))
    return Prog.Record(inp[:3], inp[4:])


def populate_targets(prog):
    """Populate the target list with the print flag arguments.

    When the '--print' flag is given without arguments, we read the config
    file to get what tlsa records we need to print; this data is placed in
    prog.target_list. When the '--print' flag _is_ given arguments, we need
    to artificially populate prog.target_list with those arguments so that
    the code that follows that will process the data can operate. This is
    that function. We will read prog.args.printrecord and put that data
    into prog.target_list.

    Args:
        prog (State): program state.

    Returns:
        Prog.RetVal.ok: always returned.
    """
    # we don't run:
    #   proto = { a for b in prog.args.printrecord for a in b }
    # instead since that randomizes the order of the data requested.
    # I would rather 'alnitak --print' not output different data every
    # time it runs, even if the flags and arguments are identical.
    # Hence, we will use the following longer code:
    proto = []
    for b in prog.args.printrecord:
        for a in b:
            if a not in proto:
                proto += [ a ]
    for p in proto:
        t = Prog.Target(p.cert)
        tlsa = Prog.Tlsa(p.params, None, None, None)
        tlsa.publish = False
        # hack the tlsa.publish member to mean that the Tlsa object
        # corresponds to a specific record, as opposed to one set
        # by the config file, where tlsa.publish is set to 'True'.
        t.tlsa += [ tlsa ]
        prog.target_list += [ t ]
    return Prog.RetVal.ok


def certificate_data(prog):
    """Given TLSA specifications, print their TLSA record data (hashes).

    Given a prog.target_list object properly populated with data (TLSA specs),
    print the TLSA certificate data for each one.

    Args:
        prog (State): program state.

    Returns:
        Prog.RetVal: return Prog.RetVal.ok if no errors occur, or else return
            Prog.RetVal.exit_failure.
    """
    retval = Prog.RetVal.ok
    prog.log.info1("+++ generating certificate data (hashes)...")
    for target in prog.target_list:
        uniq = []
        for t in target.tlsa:
            if t.params() in uniq:
                continue
            uniq += [ t.params() ]

            prog.log.info1(
                    " ++ tlsa: {}{}{}, request: {}".format(t.usage, t.selector,
                                                           t.matching,
                                                           target.domain))
            try:
                data = get_data(prog, target.domain, t)
                for d in data:
                    prog.log.info1(
                            "  + cert: {}\n  + data: {}".format(d[0], d[1]))
                    if not (prog.log.quiet
                                    or prog.log.type == Prog.LogType.stdout):
                        print("{} {} {} {} {}".format(
                                d[0], t.usage, t.selector, t.matching, d[1]))

            except (Except.FunctionError, Except.InternalError,
                    Except.DNSProcessingError) as ex:
                prog.log.error(ex.message)
                retval = Prog.RetVal.exit_failure
                continue

    return retval


def get_data(prog, domain, tlsa):
    """Return certificate data (hashes) for the TLSA specs given.

    Args:
        prog (State): program state.
        target (Target): contains the Tlsa object to read the data from, along
            with the certificate to use or directory to look for the
            certificates in.

    Returns:
        list([str, str]): a list of lists, where the inner list has exactly
            two elements: the certificate file and the data associated to it.

    Raises:
        Except.FunctionError: if generating the certificate data failed in
            any way.
    """
    # first, let's see if 'raw' exists as a file
    name = try_as_file(domain)

    # if 'None', then try as a domain to return a file
    if not name:
        name = try_as_domain(prog, domain)

    # files is now a file or a raw list (or else an exception was raised)
    if type(name) is list:
        grps = archive_groups(name)
        if grps:
            cert = [ certop.get_xive(tlsa.usage, g) for g in grps ]
        else:
            cert = [ certop.get_xive(tlsa.usage, name) ]
        if not cert:
            raise Except.FunctionError(
                "no recognized files in directory '{}'".format(domain))
    else:
        cert = [ name ]

    return [ [ c, certop.get_hash(tlsa.selector, tlsa.matching,
                                  certop.read_cert(c, tlsa.usage)) ]
             for c in cert ]


def try_as_file(inp):
    """Read the input and try to resolve it as an extant _file_.

    This function will take the input and check if it exists as a file.
    If so, then return the pathlib.Path object of the absolute path of the
    file, or else return 'None'. Note that the returned file will not be
    resolved if it is returned.

    Args:
        inp (str): input to evaluate.
        inp (str): either an absolute or releative path that is the location
            of the certificate, or else a directory that contains certificates
            named in the Let's Encrypt format ('cert.pem' or 'cert1.pem' or
            'fullchain.pem' etc.). If the value does not resolve to an extant
            file or directory, then interpret it as a domain directory name
            in the Let's Encrypt directory (e.g. 'example.com'), or else
            prepended with 'live/' or 'archive/' (e.g. 'archive/example.com').

    Returns:
        pathlib.Path: if the file exists, either as an absolute path or as
            a path relative to the working directory, then return the absolute
            path of the file. Note that any path symlinks are not resolved.
        None: otherwise.

    Raises:
        Except.FunctionError: raised if the input file exists and there was an
            error resolving the path.
    """
    file = pathlib.Path(inp)

    if not file.is_absolute():
        file = pathlib.Path.cwd() / file

    if not file.exists():
        return None

    try:
        # this will throw if it is a symlink that has a loop in it so that it
        # never points to a base file.
        if file.is_file():
            return file
    except OSError as ex:
        raise Except.FunctionError("resolving file '{}' failed: {}".format(
                                                file, ex.strerror.lower() ) )
    return None


def try_as_domain(prog, inp):
    """Read the input and try to resolve it as an extant _directory_.

    This function will take the input and check if it is a directory that
    exists, either as it is or else in the Let's Encrypt directory (i.e., in
    /etc/letsencrypt or /etc/letsencrypt/live or /etc/letsencrypt/archive).
    If so, then try to find the appropriate certificate file inside the
    directory and return it as an absolute path. Note that if the input _is_
    a directory, more than one certificate file may be suitable, so a list
    is returned.

    If the input is not a directory, then we try to treat it as a file.
    Typically, we will have already tried to do that before we called this
    function; by doing it again here, the difference is that the path will
    have been completed with the current working directory before, and now
    here it is done with the Let's Encrypt parent directory.

    Args:
        prog (State): program state.
        inp (str): input to evaluate.

    Returns:
        [ list(pathlib.Path) ]: if the input is a directory, then return a
            list of files in the directory.
        pathlib.Path: if the input is not a directory but a file in the
            Let's Encrypt directory, then return the absolute path of the
            file.

    Raises:
        Except.FunctionError: if no extant file or directory could be found,
            or there were errors resolving the path.
    """
    absolute = False
    if ( (inp[:5] == "live/" and len(inp) > 5) or
            (inp[:8] == "archive/" and len(inp) > 8) ):
        cont = prog.letsencrypt_directory / inp
    else:
        cont = pathlib.Path(inp)
        if cont.is_absolute():
            absolute = True
            # if the file is an absolute path, then we will have already done
            # a check on it before that it's a file; so later on we won't do
            # this check again. If the file is _not_ an absolute path, then
            # before we completed the path from the current working direcotry;
            # here, we'll complete it instead from the Let's Encrypt parent
            # directory.
        else:
            cont = prog.letsencrypt_live_directory / inp

    try:
        if cont.is_dir():
            files = [ cont / f.name for f in os.scandir(str(cont))
                                                            if f.is_file() ]
            if files:
                return files
            raise Except.FunctionError(
                                "no certificates in '{}' found".format(cont))
        elif not absolute:
            file = try_as_file(str(cont))
            if file:
                return file
            raise Except.FunctionError(
                        "certificate '{}' could not be resolved".format(inp))
        else:
            raise Except.FunctionError(
                        "certificate '{}' could not be resolved".format(inp))
    except OSError as ex:
        raise Except.FunctionError("resolving file '{}' failed: {}".format(
                                                file, ex.strerror.lower() ) )


def archive_groups(inp):
    """Create a list of related Let's Encrypt archive-like certificate files.

    For a given input that is a list of archive-like certificate files
    (e.g. 'cert1.pem', 'cert2.pem' etc.), return a list of lists, where the
    inner lists are those files grouped by the number in the file name.

    For example, for an input list:
        [ cert1.pem, chain1.pem, cert2.pem, chain2.pem, cert3.pem ],
    return:
        [ [cert1.pem, chain1.pem], [cert2.pem, chain2.pem], [cert3.pem] ].

    If the input is a list of live-like files (e.g. 'cert.pem', 'chain.pem'
    etc.), where there is no number in the file name, then return an empty
    list.

    Args:
        inp (list(pathlib.Path)): list of absolute paths of files in a
            common directory (usually a Let's Encrypt live or archive folder,
            but can be any folder).

    Returns:
        list(list(pathlib.Path)): list of lists if the input, grouped by the
            number in the file name.
    """
    nums = []
    for c in inp:
        m = re.match(r'\w+(\d+)\.pem$', c.name)
        if m:
            if m.group(1) not in nums:
                nums += [ m.group(1) ]
    return [ [ c for c in inp if re.match(r'\w+{}\.pem$'.format(n), c.name) ]
             for n in nums ]


