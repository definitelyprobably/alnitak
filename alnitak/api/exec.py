
import os
import pwd
import subprocess

from alnitak import exceptions as Except
from alnitak import prog as Prog


def formalize_string(inp, prepend=""):
    r"""Transform a byte string to a standard form.

    If the input is b'X\nY\nZ' and 'prepend' is set to 'A', then
    transform to 'AX\nAY\nAZ'.

    Args:
        inp (bytes): input byte string.
        prepend (str): string to prepend to lines in 'inp'. Default value
            is the empty string.

    Returns:
        str: explained above.
    """
    return "\n".join( [ "{}{}".format(prepend,i)
                                        for i in inp.decode().splitlines() ] )


def get_gid(api):
    """Return a GID value.

    If the 'api' object has a 'uid' value that is 'None', then return
    'None'. Otherwise, get the GID value from the passwd file.
    Currently, this function will get a GID value first from the /etc/group
    file if 'api.gid' is not 'None', but the config file reading
    functions do not ever set this value to anything but 'None' right now.

    Args:
        api (ApiExec):

    Returns:
        int: GID value or else 'None' if 'api.uid' is 'None'.

    Raises:
        PrivError: if no GID value could be obtained, which will be if no
            GID value is present in the passwd file.
    """
    if api.gid == None:
        if api.uid == None:
            return None

        try:
            return pwd.getpwuid(api.uid).pw_gid
        except KeyError:
            pass

        raise Except.PrivError("getting GID value failed: no GID value for user '{}' found".found(api.uid))

    try:
        return int(api.gid)
    except ValueError:
        pass

    try:
        return grp.getgrnam(api.gid).gr_gid
    except KeyError:
        pass

    try:
        if api.uid != None:
            return pwd.getpwuid(api.uid).pw_gid
    except KeyError:
        pass

    raise Except.PrivError("getting GID value failed: no group or user GID value for '{}' found".found(api.gid))



def drop_privs(api):
    """Drop privileges of the running process.

    Will first set the umask to 0027, then set the groups to those of the
    user number 'api.uid', then finally set the new GID and UID.

    Args:
        api (ApiExec): object containing the UID and GID values to drop
            to.

    Returns:
        NoneType: always returns 'None'.

    Raises:
        PrivError: raised for any errors encountered.
    """
    if api.uid == None:
        return None

    gid = get_gid(api)

    try:
        os.umask(0o027)
    except OSError as ex:
        raise Except.PrivError("setting umask failed: {}".format(ex.strerror))

    try:
        os.setgroups( os.getgrouplist(pwd.getpwuid(api.uid).pw_name, gid) )
    except KeyError:
        raise Except.PrivError("dropping privileges failed: could not set new group permissions")

    try:
        os.setgid(gid)
    except OSError as ex:
        raise Except.PrivError("droping GID privileges to group '{}' failed: {}".format(gid, ex.strerror.lower()))

    try:
        os.setuid(api.uid)
    except OSError as ex:
        raise Except.PrivError("droping UID privileges to user '{}' failed: {}".format(api.uid, ex.strerror.lower()))


def drop_privs_lambda(api):
    """Return a lambda function of the drop_privs(api) function."""
    return lambda : drop_privs(api)



def api_publish(prog, api, tlsa, hash):
    """Create (publish) a DANE TLSA record.

    Args:
        prog (State): not changed.
        api (ApiExec): details of the program to run.
        tlsa (Tlsa): details of the DANE TLSA record to publish.
        hash (str): DANE TLSA 'certificate data' (hash) to publish.

    Returns:
        NoneType: always returns 'None'.

    Raises:
        DNSSkipProcessing: if the process to run returned '1', meaning
            that the DANE TLSA record was already up.
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSNoReturnError: if an error occurred, but the program called
            indicated that Alnitak should not exit with an error exit
            code.
    """
    prog.log.info2(
        "  + calling external program to publish TLSA DNS record: {}".format(
                                                                tlsa.pstr()))
    prog.log.info3("    - program: {}".format(api.rstr()))
    environ = { "PATH":
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "IFS": " \t\n",
                "TLSA_PARAM": "{}{}{}".format(
                                tlsa.usage, tlsa.selector, tlsa.matching),
                "TLSA_USAGE": tlsa.usage,
                "TLSA_SELECTOR": tlsa.selector,
                "TLSA_MATCHING": tlsa.matching,
                "TLSA_PORT": tlsa.port,
                "TLSA_PROTOCOL": tlsa.protocol,
                "TLSA_DOMAIN": tlsa.domain,
                "TLSA_HASH": hash,
                "TLSA_OPERATION": "publish" }

    try:
        proc = subprocess.Popen(api.command, env=environ,
                                preexec_fn=drop_privs_lambda(api),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as ex:
        raise Except.DNSProcessingError(
                "command '{}': file not found".format(ex.filename))
    except OSError as ex:
        raise Except.DNSProcessingError(
                "command '{}': {}".format(ex.filename, ex.strerror.lower()))
    except subprocess.SubprocessError as ex:
        raise Except.DNSProcessingError("command '{}' failed: {}".format(
                                            api.command[0], str(ex).lower()))

    try:
        stdout, stderr = proc.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        raise Except.DNSProcessingError(
                "command '{}': process timed out (300s)".format(api.command[0]))

    prog.log.info3(
            "    - command returned (exit code): {}".format(proc.returncode))

    if stdout:
        prog.log.info2("    - command returned:\n{}".format(
                                formalize_string(stdout, "(stdout) ")))

    if stderr:
        prog.log.info2("    - command returned:\n{}".format(
                                formalize_string(stderr, "(stderr) ")))

    if proc.returncode == 0:
        return
    if proc.returncode == 1:
        raise Except.DNSSkipProcessing("TLSA record is already up")

    errmsg = "publishing TLSA record: external program '{}' returned exit code {}".format(api.command[0], proc.returncode)

    if proc.returncode >= 128:
        raise Except.DNSNoReturnError(errmsg)
    raise Except.DNSProcessingError(errmsg)



def api_delete(prog, api, tlsa, hash1, hash2):
    """Delete a DANE TLSA record.

    Args:
        prog (State): not changed.
        api (ApiExec): details of the program to run.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        hash1 (str): DANE TLSA 'certificate data' (hash) to delete.
        hash2 (str): DANE TLSA 'certificate data' (hash) to check if up
            'live' before which 'hash1' can be deleted. If has the value
            'None', then 'hash1' is unconditionally deleted.

    Returns:
        NoneType: always returns 'None'.

    Raises:
        DNSNotLive: if the process to run returned '1', meaning that the
            DANE TLSA hash 'hash2' was not yet up.
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSNoReturnError: if an error occurred, but the program called
            indicated that Alnitak should not exit with an error exit
            code.
    """
    prog.log.info2("  + calling external program to delete TLSA DNS record: _{}._{}.{}".format(tlsa.port, tlsa.protocol, tlsa.domain))
    prog.log.info3("    - program: {}".format(api.rstr()))
    environ = { "PATH":
                "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
                "IFS": " \t\n",
                "TLSA_PARAM": "{}{}{}".format(
                                tlsa.usage, tlsa.selector, tlsa.matching),
                "TLSA_USAGE": tlsa.usage,
                "TLSA_SELECTOR": tlsa.selector,
                "TLSA_MATCHING": tlsa.matching,
                "TLSA_PORT": tlsa.port,
                "TLSA_PROTOCOL": tlsa.protocol,
                "TLSA_DOMAIN": tlsa.domain,
                "TLSA_HASH": hash1,
                "TLSA_OPERATION": "delete" }

    if hash2:
        environ["TLSA_LIVE_HASH"] = hash2

    try:
        proc = subprocess.Popen(api.command, env=environ,
                                preexec_fn=drop_privs_lambda(api),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as ex:
        raise Except.DNSProcessingError(
                "command '{}': file not found".format(ex.filename))
    except OSError as ex:
        raise Except.DNSProcessingError(
                "command '{}': {}".format(ex.filename, ex.strerror.lower()))
    except subprocess.SubprocessError as ex:
        raise Except.DNSProcessingError("command '{}' failed: {}".format(
                                            api.command[0], str(ex).lower()))

    try:
        stdout, stderr = proc.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        raise Except.DNSProcessingError(
                "command '{}': process timed out (300s)".format(api.command[0]))

    prog.log.info3(
            "    - command returned (exit code): {}".format(proc.returncode))

    if stdout:
        prog.log.info2("    - command returned:\n{}".format(
                                formalize_string(stdout, "(stdout) ")))

    if stderr:
        prog.log.info2("    - command returned:\n{}".format(
                                formalize_string(stderr, "(stderr) ")))

    if proc.returncode == 0:
        return
    if proc.returncode == 1:
        raise Except.DNSNotLive("TLSA record not up yet")

    errmsg = "deleting TLSA record: external program '{}' returned exit code {}".format(api.command[0], proc.returncode)

    if proc.returncode >= 128:
        raise Except.DNSNoReturnError(errmsg)
    raise Except.DNSProcessingError(errmsg)


def get_api(prog, input_list, state):
    """Create an ApiExec object from a config file line.

    Given an 'api = exec ...' line in a config file, construct
    and return an ApiExec object, or else 'None' if an error is
    encountered.

    Args:
        prog (State): not changed.
        input_list (list(str)): a list of whitespace-delimited strings
            corresponding to the inputs following 'api = exec'
            (i.e., the 'inputs' of the 'api' parameter, less the first
            'exec' input).
        state (ConfigState): class to record config file errors.

    Returns:
        ApiExec: creates an ApiExec object from the arguments.
        None: if an error is encountered.
    """
    if input_list[0][0:4] == "uid:":
        uid = get_api_uid(prog, input_list[0][4:], state)
        if uid == None:
            return None
        comms = input_list[1:]
    else:
        uid = None
        comms = input_list

    if len(comms) == 0:
        state.add_error(prog, "'exec' api scheme given no command to run")
        return None

    return Prog.ApiExec(comms, uid=uid)


def get_api_uid(prog, uid, state):
    """Extract a UID from the input.

    If the input is an integer, this will just be used. If a username, the
    UID will be searched for in the passwd file.

    Args:
        prog (State): not changed.
        uid (str): the input to the 'uid' flag: this will be 'X' if
            'uid:X' was found on the config line.
        state (ConfigState): class to record config file errors.

    Returns:
        int: the UID value, or else 'None' if an error is found.
    """
    if len(uid) == 0:
        state.add_error(prog, "'exec' api scheme: no uid input given")
        return None

    try:
        return int(uid)
    except ValueError:
        pass

    try:
        return pwd.getpwnam(uid).pw_uid
    except KeyError:
        pass

    state.add_error(prog, "'exec' api scheme: uid input '{}' not a valid input".format(uid))
    return None


