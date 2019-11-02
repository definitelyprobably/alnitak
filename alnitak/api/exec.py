
import os
import pwd
import grp
import subprocess

from alnitak import exception
from alnitak.prog import Error


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

    If the 'api' object has a 'uid' value that is '0', then return '0'.
    Otherwise, get the GID value from the passwd file.
    Currently, this function will get a GID value first from the /etc/group
    file if 'api.gid' is not '0', but the config file reading
    functions do not ever set this value to anything but '0' right now.

    Args:
        api (ApiExec):

    Returns:
        int: GID value or else '0' if 'api.uid' is '0'.

    Raises:
        PrivError: if no GID value could be obtained, which will be if no
            GID value is present in the passwd file.
    """
    uid = api['uid']
    gid = api['gid']

    if gid == 0:
        if uid == 0:
            return 0

        try:
            return pwd.getpwuid(uid).pw_gid
        except KeyError:
            pass

        raise exception.AlnitakError( Error(3100,
                    "getting GID value failed: no GID value for user '{}' found".format(uid) ))

    try:
        return int(gid)
    except ValueError:
        pass

    try:
        return grp.getgrnam(gid).gr_gid
    except KeyError:
        pass

    try:
        if uid != 0:
            return pwd.getpwuid(uid).pw_gid
    except KeyError:
        pass

    raise exception.AlnitakError( Error(3101,
        "getting GID value failed: no group or user GID value for '{}' found".format(gid) ))


def drop_privs(api):
    """Drop privileges of the running process.

    Will first set the umask to 0027, then set the groups to those of the
    user number 'api.uid', then finally set the new GID and UID.

    Args:
        api (ApiExec): object containing the UID and GID values to drop
            to.

    Raises:
        PrivError: raised for any errors encountered.
    """
    uid = api['uid']

    if uid == 0:
        return

    gid = get_gid(api)

    try:
        os.umask(0o027)
    except OSError as ex:
        raise exception.AlnitakError( Error(3110,
                "setting umask failed: {}".format(ex.strerror.lower()) ))

    try:
        os.setgroups( os.getgrouplist(pwd.getpwuid(uid).pw_name, gid) )
    except KeyError:
        raise exception.AlnitakError( Error(3111, "dropping privileges failed: could not set new group permissions") )

    try:
        os.setgid(gid)
    except OSError as ex:
        raise exception.AlnitakError( Error(3112, "droping GID privileges to group '{}' failed: {}".format(gid, ex.strerror.lower()) ))

    try:
        os.setuid(uid)
    except OSError as ex:
        raise exception.AlnitakError( Error(3113, "droping UID privileges to user '{}' failed: {}".format(uid, ex.strerror.lower()) ))


def drop_privs_lambda(api, testing):
    """Return a lambda function of the drop_privs(api) function."""
    if testing:
        return
    return lambda : drop_privs(api)


def api_publish(state, domain, spec):
    """Create (publish) a DANE TLSA record.

        0  - record published/updated successfully,
        1  - record already up,
        2+ - publish/update failed.

    """
    target = state.targets[domain]
    api = target['api']
    record = target['records'][spec]

    environ = { #"PATH":
                #"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                #"IFS": " \t\n",
                #"RENEWED_DOMAINS": " ".join(state.renewed_domains),
                "ALNITAK_ZONE": domain,
                "ALNITAK_LETSENCRYPT_DIR": str(target['letsencrypt_directory']),
                "ALNITAK_PARAMS": "{} {} {}".format(
                                record['params']['usage'],
                                record['params']['selector'],
                                record['params']['matching_type']),
                "ALNITAK_USAGE": str(record['params']['usage']),
                "ALNITAK_SELECTOR": str(record['params']['selector']),
                "ALNITAK_MATCHING_TYPE": str(record['params']['matching_type']),
                "ALNITAK_PORT": str(record['port']),
                "ALNITAK_PROTOCOL": str(record['protocol']),
                "ALNITAK_DOMAIN": str(record['domain']),
                "ALNITAK_CERT_DATA": str(record['new']['data']),
                "ALNITAK_OPERATION": "publish" }

    if record['new']['update']:
        environ['ALNITAK_UPDATE'] = record['new']['update']

    try:
        proc = subprocess.Popen(api['command'], env=environ,
                                preexec_fn=drop_privs_lambda(
                                                    api, state.testing_mode),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as ex:
        # exception does not seem to be set properly.
        # 3.4.2: strerror: "No such file or directory: 'file'"
        #        filename: None
        # 3.6.7: strerror: "No such file or directory: 'file'"
        #        filename: "file"
        # Neither of these are correct...
        raise exception.AlnitakError( Error(3120,
                "command '{}': file not found".format(api['command'][0]) ))
    except OSError as ex:
        raise exception.AlnitakError( Error(3121,
                "command '{}': {}".format(
                    api['command'][0], ex.strerror.lower()) ))
    except subprocess.SubprocessError as ex:
        raise exception.AlnitakError( Error(3122,
                "command '{}' failed: {}".format(
                    api['command'][0], str(ex).lower()) ))

    try:
        stdout, stderr = proc.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        raise exception.AlnitakError( Error(3123,
                "command '{}': process timed out (300s)".format(
                    api['command'][0]) ))

    # TODO
    #prog.log.info3(
    #        "    - command returned (exit code): {}".format(proc.returncode))

    # TODO
    #if stdout:
    #    prog.log.info2("    - command returned:\n{}".format(
    #                            formalize_string(stdout, "(stdout) ")))

    # TODO
    #if stderr:
    #    prog.log.info2("    - command returned:\n{}".format(
    #                            formalize_string(stderr, "(stderr) ")))

    # record was published
    if proc.returncode == 0:
        record['new']['published'] = True
        return

    # record was already up
    if proc.returncode == 1:
        record['new']['published'] = True
        record['new']['is_up'] = True
        return

    raise exception.AlnitakError( Error(3124,
            "publishing TLSA record: external program '{}' returned exit code {}".format(api['command'][0], proc.returncode) ))


def api_read_delete(state, domain, spec, cleanup = None):
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


        0  - record deleted
        1  - new record is not up yet
        2  - new record is up, but deletion failed
        3+ - checking record is up failed

    """
    target = state.targets[domain]
    api = target['api']
    record = target['records'][spec]

    # remove record in delete unconditionally
    if cleanup:
        cert_data = cleanup

    # remove record in prev if record in new is up
    else:
        cert_data = record['prev']['data']
        cert_data_live = record['new']['data']

    environ = { #"PATH":
                #"/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
                #"IFS": " \t\n",
                #"RENEWED_DOMAINS": " ".join(prog.renewed_domains),
                "ALNITAK_ZONE": domain,
                "ALNITAK_LETSENCRYPT_DIR": str(target['letsencrypt_directory']),
                "ALNITAK_PARAMS": "{} {} {}".format(
                                record['params']['usage'],
                                record['params']['selector'],
                                record['params']['matching_type']),
                "ALNITAK_USAGE": str(record['params']['usage']),
                "ALNITAK_SELECTOR": str(record['params']['selector']),
                "ALNITAK_MATCHING_TYPE": str(record['params']['matching_type']),
                "ALNITAK_PORT": str(record['port']),
                "ALNITAK_PROTOCOL": str(record['protocol']),
                "ALNITAK_DOMAIN": str(record['domain']),
                "ALNITAK_OPERATION": "delete" }

    # only set this if there is a record to delete. Potentially, there may not
    # be if the new record matches the prev one (e.g. for 2xx records).
    if cert_data:
        environ["ALNITAK_CERT_DATA"] = cert_data

    if not cleanup:
        environ["ALNITAK_LIVE_CERT_DATA"] = cert_data_live

    try:
        proc = subprocess.Popen(api['command'], env=environ,
                                preexec_fn=drop_privs_lambda(
                                                    api, state.testing_mode),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as ex:
        # exception does not seem to be set properly.
        # 3.4.2: strerror: "No such file or directory: 'file'"
        #        filename: None
        # 3.6.7: strerror: "No such file or directory: 'file'"
        #        filename: "file"
        # Neither of these are correct...
        raise exception.AlnitakError( Error(3130,
                "command '{}': file not found".format(api['command'][0]) ))
    except OSError as ex:
        raise exception.AlnitakError( Error(3131,
                "command '{}': {}".format(
                    api['command'][0], ex.strerror.lower()) ))
    except subprocess.SubprocessError as ex:
        raise exception.AlnitakError( Error(3132,
                "command '{}' failed: {}".format(
                    api['command'][0], str(ex).lower()) ))

    try:
        stdout, stderr = proc.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        raise exception.AlnitakError( Error(3133,
                "command '{}': process timed out (300s)".format(
                    api['command'][0]) ))

    # TODO
    #prog.log.info3(
    #        "    - command returned (exit code): {}".format(proc.returncode))

    # TODO
    #if stdout:
    #    prog.log.info2("    - command returned:\n{}".format(
    #                            formalize_string(stdout, "(stdout) ")))

    # TODO
    #if stderr:
    #    prog.log.info2("    - command returned:\n{}".format(
    #                            formalize_string(stderr, "(stderr) ")))

    if cleanup:
        if proc.returncode == 0:
            # remove cleanup from delete
            state.remove_delete_record(domain, spec, cleanup)
            return
    else:

        # record was deleted
        if proc.returncode == 0:
            record['new']['is_up'] = True
            return

        # live cert not up yet.
        if proc.returncode == 1:
            return

        # record is up, but deletion failed, set is_up to True
        if proc.returncode == 2:
            record['new']['is_up'] = True


    # FIXME: capture stderr from command and report it here.
    raise exception.AlnitakError( Error(3134,
            "deleting TLSA record '{} {} {}' (_{}._{}.{}): external program '{}' returned exit code {}".format(
                record['params']['usage'],
                record['params']['selector'],
                record['params']['matching_type'],
                record['port'],
                record['protocol'],
                record['domain'],
                api['command'][0],
                proc.returncode) ))




def get_api(prog, domain, input_list, state):
    """Create an ApiExec object from a config file line.

    Given an 'api = exec ...' line in a config file, construct
    and return an ApiExec object, or else 'None' if an error is
    encountered.

    Args:
        prog (State): not changed.
        domain (str): the domain (section) the api command is in. Note: can
            be 'None' if the api command was global.
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
        uid = 0
        comms = input_list

    if len(comms) == 0:
        state.add_error(prog, "'exec' api scheme given no command to run")
        return None

    api = Prog.ApiExec(comms, uid=uid)
    if domain:
        api.set_domain(domain)
    return api

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

