
import os
import pwd
import subprocess

from alnitak import exceptions as Except


def formalize_string(str, prepend=""):
    return "\n".join( [ "{}{}".format(prepend,i)
                                        for i in str.decode().splitlines() ] )


def get_gid(api):
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
    if api.uid == None:
        return

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
    return lambda : drop_privs(api)



def publish(prog, api, tlsa, hash):
    """
    Calls:
        - None

    Exceptions:
        - Except.DNSNotLive
        - Except.DNSProcessingError
    """
    prog.log.info2(
        "  + calling external program to publish TLSA DNS record: {}".format(
                                                                tlsa.pstr()))
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

    if proc.returncode >= 200:
        raise Except.DNSNoReturnError(errmsg)
    raise Except.DNSProcessingError(errmsg)



def delete(prog, api, tlsa, hash1, hash2):
    """
    Calls:
        - None

    Exceptions:
        - Except.DNSNotLive
        - Except.DNSProcessingError
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

    if proc.returncode >= 200:
        raise Except.DNSNoReturnError(errmsg)
    raise Except.DNSProcessingError(errmsg)

