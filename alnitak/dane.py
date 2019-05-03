
import os
import pathlib
from importlib import import_module

from alnitak import prog as Prog
from alnitak import exceptions as Except
from alnitak import certop



def init_dane_directory(prog):
    """Create the dane directory and dane domain subdirectories.

    A. create dane_directory (DD) and its parents and DD has mode 0700.
    B. [recreate_dane]: chown root:root DD
    C. [recreate_dane]: chmod 0700 DD.
    D. get list of live directories (LD)
    E. make LD names in DD (LDD); if LDD already exists, that is OK
    F. get symlinks in LD
    G. set dane_domain_directories
    H. [recreate_dane]: remove symlink name in LDD; if no file (as there
       should be), fine
    I. create symlink name in LDD
        if [recreate_dane]: if file exists, is an error
        else: if file exists, must be a symlink
    J. all domains in config should exist on the system (i.e., no missing
       Let's Encrypt certificates).
    K. set dane_domain_directories

    This function will check to see if the dane directory is 'sane' and
    will create the necessary folders and symlinks if they are missing.
    It will not try to fix mistakes unless 'prog.recreate_dane' is set
    to 'True': it will exit if errors are encountered.

    Note that even when 'prog.recreate_dane' is set to 'True', we will
    not remove files or folders that are no longer used (e.g. if a
    previous config file defined the domain 'x.com' and this program
    created a directory 'x.com' in the dane directory previously, if the
    config file now replaces 'x.com' with 'y.com', we will certainly
    create a new directory called 'y.com', but we will NOT remove 'x.com').
    If a completely clean directory is required, the user should manually
    remove the dane directory and then call this program to create a new
    one from scratch.

    Args:
        prog (State): program internal state.

    Returns:
        RetVal: returns 'RetVal.exit_failure' if any errors are
            encountered, and 'RetVal.ok' otherwise.
    """
    prog.log.info2("+++ initializing 'dane' direcory: '{}'".format(
                                                        prog.dane_directory))

    # operation: A
    # create dane directory if it doesn't exist. We'll restrict the
    # permissions of this directory to 700, following the letsencrypt
    # directories.
    try:
        prog.dane_directory.mkdir(mode=0o700, parents=True)
    except FileExistsError as ex:
        # Note: this catch can be removed for python 3.5+ since mkdir()
        # accepts the 'exist_ok' parameter.
        if prog.dane_directory.is_dir():
            # if directory exists, that is fine
            pass
        else:
            prog.log.error(
                "creating dane directory '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
            return Prog.RetVal.exit_failure
    except OSError as ex:
        prog.log.error(
            "creating dane directory '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return Prog.RetVal.exit_failure


    # operation: B
    # if the dane directory alrwady exists, then its permissions might not
    # be correct. If told to recreate the directory, fix its permissions now:
    if prog.recreate_dane:
        prog.log.info2(
                " ++ checking/fixing mode of dane direcory: should be '0700'")
        try:
            prog.dane_directory.chmod(0o700)
        except OSError as ex:
            prog.log.error(
                "changing permissions of dane directory '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
            return Prog.RetVal.exit_failure

        prog.log.info2(
            " ++ checking/fixing owner of dane direcory: should be 'root:root'")
        try:
            # operation: C
            # when running tests (unless run as root) we won't have
            # permissions to do this, so we have to skip this when testing
            if not prog.testing_mode:
                os.chown(str(prog.dane_directory), 0, 0)
        except OSError as ex:
            prog.log.error(
                    "changing owner of dane directory '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
            return Prog.RetVal.exit_failure


    # operation: D
    # get a list of directories in the letsencrypt live directory (named after
    # domains)
    prog.log.info3("  + domain directories in the live direcory '{}':".format(
                                            prog.letsencrypt_live_directory))
    try:
        live_domains = [ f for f in prog.letsencrypt_live_directory.iterdir()
                            if f.is_dir() ]
    except OSError as ex:
        prog.log.error(
                "letsencrypt live directory '{}': {}".format(
                                            ex.filename, ex.strerror.lower()))
        return Prog.RetVal.exit_failure
    for d in live_domains:
        prog.log.info3("    - {}".format(d))


    retval = Prog.RetVal.ok

    # for each domain folder found in the list 'live_domains' populated above,
    # we need to do 2 things:
    #   1) create an identically-named folder in the dane directory
    #   2) populate that directory with symlinks to the _symlinks_ in the
    #      live directory
    for d in live_domains:

        dane_d = pathlib.Path(prog.dane_directory / d.name)

        prog.log.info2(
                " ++ checking dane domain directory '{}'".format(dane_d))

        # operation: E
        # implement 1): create dane/$(basename d)
        try:
            dane_d.mkdir()
        except FileExistsError as ex:
            # Note: this catch can be removed for python 3.5+ since mkdir()
            # accepts the 'exist_ok' parameter.
            if prog.dane_directory.is_dir():
                # if directory exists, that is fine
                pass
            else:
                prog.log.error(
                    "creating dane domain directory '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
                retval = Prog.RetVal.exit_failure
                continue
        except OSError as ex:
            prog.log.error(
                    "creating dane domain directory '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
            retval = Prog.RetVal.exit_failure
            continue

        # operation: F
        # implement 2): first, we get a list of symlinks in the live domain
        # directory
        prog.log.info3(
            "  + creating symlinks to live domain symlinks...".format(dane_d))
        try:
            link_list = [ f.name for f in d.iterdir()
                                        if f.is_symlink() and f.is_file() ]
        except OSError as ex:
            prog.log.error(
                    "letsencrypt (live) domain directory '{}': {}".format(
                                            ex.filename, ex.strerror.lower()))
            retval = Prog.RetVal.exit_failure
            continue


        # operation: G
        # let's add the domain directory and the symlinks inside it to
        # prog.dane_domain_directories
        prog.dane_domain_directories[d.name] = link_list


        # implement 2): ...then, we create symlinks in the dane domain
        # directory, pointing to the live domain symlinks
        for l in link_list:
            prog.log.info3("    - {}".format(l))

            dane_l = pathlib.Path(dane_d / l)

            # operation: H
            # if recreating the dane directory, remove the file even if it is
            # OK and we'll just create a new symlink.
            try:
                if prog.recreate_dane:
                    dane_l.unlink()
            except FileNotFoundError:
                # file doesn't exist is fine
                pass
            except OSError as ex:
                prog.log.error("removing symlink '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
                retval = Prog.RetVal.exit_failure
                continue


            # operation: I
            try:
                dane_l.symlink_to( relative_to(dane_l, d / l) )
            except FileExistsError as ex:
                # when recreating the directory, the file _should not_
                # exist...
                if prog.recreate_dane:
                    prog.log.error(
                            "recreating symlink '{}': file exists".format(
                                                                ex.filename))
                    retval = Prog.RetVal.exit_failure
                    continue
                else:
                    try:
                        target_file = pathlib.Path(os.readlink(str(dane_l)))
                    except OSError as ex:
                        prog.log.error(
                                "dane file '{}' is not a symlink".format(
                                                                  ex.filename))
                        retval = Prog.RetVal.exit_failure
                        continue

                    #if not target_file.is_symlink():
                    #    prog.log.error("dane symlink '{}' resolves to '{}', which is not a symlink itself".format(dane_l, target_file))
                    #    retval = False
                    #    continue
            except OSError as ex:
                prog.log.error("recreating symlink '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
                retval = Prog.RetVal.exit_failure
                continue

    if not retval == Prog.RetVal.ok:
        return retval

    # operation: J
    # the dane directory and symlinks have been created (or are fine). Now,
    # every domain in the prog.target_list MUST exist in
    # prog.dane_domain_directories:
    for t in prog.target_list:
        if t.domain not in prog.dane_domain_directories:
            prog.log.error("domain '{}' from config file does not have a corresponding letsencrypt directory".format(t.domain))
            retval = Prog.RetVal.exit_failure

    # operation: K
    # now, prog.dane_domain_directories is a dictionary containing all
    # directory names in the letsencrypt live directory, but we're not
    # interested in _all_ of them, just the ones being used by this
    # program; that is, only those defined in the config file (and hence
    # in prog.target_list). So, let's remove the other ones:
    new_dict = { }
    for d in prog.dane_domain_directories:
        if d in [ t.domain for t in prog.target_list ]:
            new_dict[d] = prog.dane_domain_directories[d]

    prog.dane_domain_directories = new_dict
    prog.log.info3(" ++ dane_domain_directories: {}".format(
                                                prog.dane_domain_directories))

    return retval

def set_renewed_domains(prog):
    """Check if the environment parameter 'RENEWED_DOMAINS' is set.

    Args:
        prog (State): program internal state.

    Returns:
        RetVal: always returns 'RetVal.ok'.
    """
    prog.log.info1("+++ checking environment parameter 'RENEWED_DOMAINS'")
    try:
        prog.renewed_domains = os.environ['RENEWED_DOMAINS'].split()
    except KeyError:
        # Maybe never return an error if not set, even in posthook mode.
        #if prog.args.post:
        #    prog.log.error(
        #            "no RENEWED_DOMAINS parameter set in the environment")
        #    return Prog.RetVal.exit_failure
        prog.log.info1("  + not set")
        return Prog.RetVal.ok

    for i in prog.renewed_domains:
        prog.log.info1("  + {}".format(i))
    if not prog.renewed_domains:
        prog.log.info1("  + empty")

    return Prog.RetVal.ok

def live_to_archive(prog):
    """Move dane symlinks from pointing to live certs to archive certs.

    Args:
        prog (State): program internal state.

    Returns:
        RetVal: returns 'RetVal.continue_failure' if any error is
            encountred, and returns 'RetVal.ok' otherwise.
    """
    prog.log.info1("+++ moving dane symlinks to point from live to archive")
    retval = Prog.RetVal.ok

    # loop over target_list rather than the keys in dane_domain_directories
    # since we'll be adding certs to the target
    for t in prog.target_list:
        for l in prog.dane_domain_directories[t.domain]:

            # the (full path) dane symlink
            dane_l = prog.dane_directory / t.domain / l
            prog.log.info2(" ++ dane: {}".format(dane_l))

            try:
                # the dane file MUST resolve to something (i.e. be a symlink)
                resolv1 = pathlib.Path(os.readlink(str(dane_l)))
            except OSError as ex:
                prog.log.error(
                        "dane file '{}' is not a symlink".format(ex.filename))
                retval = Prog.RetVal.continue_failure
                continue

            prog.log.info3("    => {}".format(resolv1))

            if not resolv1.is_absolute():
                resolv1 = dane_l.parent / resolv1

                try:
                    presolv1 = resolv1.parent.resolve()
                except FileNotFoundError as ex:
                    prog.log.error(
                       "path in live certificate file '{}' not found".format(
                                                               ex.filename))
                    retval = Prog.RetVal.continue_failure
                    continue
                except RuntimeError as ex:
                    prog.log.error("recursive loop in resolving live certificate file '{}'".format(ex.filename))
                    retval = Prog.RetVal.continue_failure
                    continue

                resolv1 = presolv1 / resolv1.name


            # 'resolv1' may or may not be a symlink: ordinarily it should
            # be a symlink, but if it's already been processed by a
            # pre-hook command, then it will be an archive (regular) file.
            if resolv1.is_symlink():
                try:
                    archive_f = pathlib.Path(os.readlink(str(resolv1)))
                except OSError as ex:
                    prog.log.error(
                        "live file '{}' is not a symlink".format(ex.filename))
                    retval = Prog.RetVal.continue_failure
                    continue

                prog.log.info3("       => {}".format(archive_f))

            else:
                # if not a symlink, we assume it's been processed by
                # prehook already.
                prog.log.info2("    points to a regular file")
                continue

            if not archive_f.is_absolute():
                archive_f = resolv1.parent / archive_f
                try:
                    archive_f = archive_f.resolve()
                except FileNotFoundError as ex:
                    prog.log.error("path in archive certificate file '{}' not found".format(ex.filename))
                    retval = Prog.RetVal.continue_failure
                    continue
                except RuntimeError as ex:
                    prog.log.error("recursive loop in resolving archive certificate file '{}'".format(ex.filename))
                    retval = Prog.RetVal.continue_failure
                    continue

            try:
                dane_l.unlink()
            except FileNotFoundError as ex:
                prog.log.error(
                        "dane symlink '{}' not found".format(ex.filename))
                retval = Prog.RetVal.continue_failure
                continue
            except OSError as ex:
                prog.log.error(
                        "removing dane symlink '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
                retval = Prog.RetVal.continue_failure
                continue

            try:
                dane_l.symlink_to( relative_to(dane_l, archive_f) )
            except FileExistsError as ex:
                # seeing as we deleted this file soon before this point...
                prog.log.error(
                    "recreating symlink '{}': file exists".format(ex.filename))
                retval = Prog.RetVal.continue_failure
                continue
            except OSError as ex:
                prog.log.error("recreating symlink '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
                retval = Prog.RetVal.exit_failure
                continue

            prog.log.info2("    => moved to {}".format(archive_f))

            t.add_cert(dane_l, resolv1, archive_f)

    return retval

def process_data(prog):
    """Process datafile lines.

    Data is organized in 'groups', which are collections of datafile lines
    that share a common domain. First, withing every group, all the
    delete lines are processed. Then we loop over the groups again, and if
    there exist posthook lines, we call 'process_data_posthook', otherwise
    we call 'process_data_prehook'.

    Args:
        prog (State): program internal state.

    Returns:
        RetVal: returns 'RetVal.continue_failure' if any error is
            encountred, and returns 'RetVal.ok' otherwise.
    """
    retval = Prog.RetVal.ok

    for group in prog.data.groups:
        # if there are any delete lines, we should try to process them now
        for l in group.special:
            try:
                delete_dane_if_up(prog, group.target.api, l.tlsa, l.hash)
                l.write_state_off()
            except Except.DNSSkip as ex:
                prog.log.info2("  + {}".format(ex.message))
                prog.log.info2(
                        "  + TLSA record not removed; incrementing the count")
                l.increment_count()
            except Except.DNSNoReturnError as ex:
                prog.log.error(ex.message)
                prog.log.info2(
                        "  + TLSA record not removed; incrementing the count")
                l.increment_count()
            except (Except.DNSError, Except.InternalError) as ex:
                prog.log.error(ex.message)
                prog.log.info2(
                        "  + TLSA record not removed; incrementing the count")
                l.increment_count()
                retval = Prog.RetVal.continue_failure

    for group in prog.data.groups:
        if group.post:
            if process_data_posthook(prog, group):
                retval = Prog.RetVal.continue_failure
        else:
            if process_data_prehook(prog, group):
                retval = Prog.RetVal.continue_failure

    return retval

def delete_dane_if_up(prog, api, tlsa, hash1, hash2 = None):
    """Delete a DANE TLSA record.

    Basically, all this function does is attempt to delete 'hash1':

    hash1 = {the old TLSA hash: need to see if it is up and then delete it}
    hash2 = None

    hash1 = {the old TLSA hash: if it AND hash2 are up, then delete it}
    hash2 = {the new TLSA hash: already published, needs to be up before hash1
             can be deleted}

    This function is called in three situations:
        1. when reading a delete line, so basically when told to delete a
            record.
        2. when reading a posthook line on a non-renewed domain, after the TTL
            value has passed and we want to delete an old hash
        3. when reading a posthook line on a renewed domain whose pending state
            is '0', so basically we have renewed again and we need to delete
            the previous 'new' hash that was published.

    Note that a failure of 1. causes repeated attempts at 1; a failure of 2
    causes repeated attempts at 2; and a failure of 3 causes a delete line to
    be made, and so causes 1.

    Args:
        prog (State): program internal state.

    Returns:
        NoneType: always returns 'None'.

    Raises:
        DNSNotLive: if DANE record not up yet.
        DNSProcessingError: if an error occurs that should cause Alnitak
            to exit with an error code.
        DNSNoReturnError: if an error occurs that requests that Alnitak do
            not exit with an error code (raised from 'exec.delete').
    """
    prog.log.info1(
            "+++ attempting to delete TLSA DNS record: {}".format(tlsa.pstr()))

    if api.type == Prog.ApiType.exec:
        from alnitak.api.exec import api_delete
        api_delete(prog, api, tlsa, hash1, hash2)
    else:
        apimod = import_module('alnitak.api.' + api.type.value)
        
        # get a dict of all the records up
        records = apimod.api_read(prog, api, tlsa)

        # if we need to check if hash2 is up, then do that now
        if hash2:
            for r in records:
                if r == hash2:
                    break
            else:
                raise Except.DNSNotLive("TLSA record not up yet")

        # if the hash is in 'records', then we need to delete that
        # record
        for r in records:
            if r == hash1:
                apimod.api_delete(prog, api, tlsa, records[r])
                break
        else:
            raise Except.DNSNotLive("TLSA record not up yet")

def process_data_prehook(prog, group):
    """Process prehook lines.

    If the domain in the group is renewed, then call 'publish_dane',
    otherwise call 'archive_to_live'.

    Args:
        prog (State): program internal state.
        group (DataGroup): the group of prehook and/or posthook lines.

    Returns:
        bool: return 'True' for errors, 'False' otherwise.
    """
    if group.domain in prog.renewed_domains:
        prog.log.info1(
                "+++ prehook line: domain '{}' renewed".format(group.domain))
        if group.target:
            return publish_dane(prog, group)
        else:
            prog.log.error("domain '{}' renewed, but not in config file: cannot process!".format(group.domain))
            return True
    else:
        prog.log.info1(
            "+++ prehook line: domain '{}' not renewed".format(group.domain))
        # move dane symlinks back to live
        return archive_to_live(prog, group)

def process_data_posthook(prog, group):
    """Process posthook lines.

    If the domain in the group is renewed, then call
    'process_data_posthook_renewed', otherwise call
    'process_data_posthook_not_renewed'.

    Args:
        prog (State): program internal state.
        group (DataGroup): the group of prehook and/or posthook lines.

    Returns:
        bool: return 'True' for errors, 'False' otherwise.
    """
    if group.domain in prog.renewed_domains:
        prog.log.info1(
                "+++ posthook line: domain '{}' renewed".format(group.domain))
        return process_data_posthook_renewed(prog, group)

    else:
        prog.log.info1(
            "+++ posthook line: domain '{}' not renewed".format(group.domain))
        # check the posthook line state; if '0', then see if the dane is up
        # and then delete the line if it is; if '1', then retry to publish
        # the dane
        return process_data_posthook_not_renewed(prog, group)

def process_data_posthook_not_renewed(prog, group):
    """Process posthook lines for the non-renewed domain.

    For all lines in the group, if the line's pending state is '0', then
    delete the old TLSA record if the time-to-live value has passed,
    otherwise, try to publish the TLSA record again (since it must have
    failed last time).

    Args:
        prog (State): program internal state.
        group (DataGroup): the group of prehook and/or posthook lines.

    Returns:
        bool: return 'True' for errors, 'False' otherwise.
    """
    errors = False

    for l in group.post:
        if l.pending == '0':
            prog.log.info1(" ++ pending state is 0: ({}): deleting old TLSA DNS record".format(l.tlsa.pstr()))

            # cert: if set inside the try block, then use it in the
            # except catches.
            cert = None
            try:
                # check if TTL has passed
                prog.log.info2(" ++ checking TTL value has passed")
                #check_ttl(l.data.time)
                try:
                    time_now = int("{:%s}".format(prog.timenow))
                    time_published = int(l.time)
                except ValueError as ex:
                    raise Except.InternalError("time value is not an integer")

                time_passed = time_now - time_published
                prog.log.info3("  + published at: {}\n  + now: {} ({} seconds elapsed)".format(time_published, time_now, time_passed))

                if time_passed < prog.ttl:
                    raise Except.DNSSkipProcessing("time to live value ({}) hasn't passed: {} seconds remain".format(prog.ttl, prog.ttl - time_passed))


                # get cert hash
                cert = certop.get_archive(l.tlsa.usage,
                                        [ l.cert.archive for l in group.pre ])
                prog.log.info2(
                        "  + old hash: going to use cert '{}'".format(cert))

                cert_data = certop.read_cert(cert, l.tlsa.usage)
                hash = certop.get_hash( l.tlsa.selector, l.tlsa.matching,
                                             cert_data)
                prog.log.info2("  + old {}{}{} hash: {}".format(
                    l.tlsa.usage, l.tlsa.selector, l.tlsa.matching, hash))

                # check if the dns record is up
                delete_dane_if_up(prog, group.target.api, l.tlsa, hash, l.hash)

                # change the write state of the line
                l.write_state_off()

            except Except.DNSSkip as ex:
                prog.log.info2("  + {}".format(ex.message))
            except (Except.DNSError, Except.InternalError) as ex:
                errors = True
                if cert:
                    prog.log.error("{}: {}".format(cert, ex.message))
                else:
                    prog.log.error(ex.message)
        else:
            # retry publishing record
            prog.log.info1(" ++ pending state is 1: will retry publishing TLSA DNS record {}".format(l.tlsa.pstr()))
            try:
                apimod = import_module('alnitak.api.'
                                                + group.target.api.type.value)
                apimod.api_publish(prog, group.target.api, l.tlsa, l.hash)

                prog.log.info2("  + record published successfully")

                # switch the pending state of the line
                l.pending_off()

                # update the time
                l.change_time("{:%s}".format(prog.timenow))

            except Except.DNSSkip as ex:
                prog.log.info2("  + {}".format(ex.message))
                # If the record is already up, then we do not need to do any
                # further processing
                l.write_state_off()
            except Except.DNSNoReturnError as ex:
                prog.log.error(ex.message)
            except (Except.DNSError, Except.InternalError) as ex:
                prog.log.error(ex.message)
                errors = True

    # let's now see if we have _any_ posthook lines to write
    for l in group.post:
        if l.state == Prog.DataLineState.write:
            break
    else:
        # no posthook lines: remove all the prehook lines:
        prog.log.info2(
                "+++ all posthook lines processed (all records up/deleted)")
        if archive_to_live(prog, group):
            errors = True

    return errors

def process_data_posthook_renewed(prog, group):
    """Process posthook lines for the renewed domain.

    For all lines in the group, if the line's pending state is '0', then
    mark the old 'new' TLSA record for deletion, publish the renewed
    certificate's TLSA record and then try deleting the old record. If the
    pending state is '1' then just publish the renewed certificate's
    TLSA record.

    Args:
        prog (State): program internal state.
        group (DataGroup): the group of prehook and/or posthook lines.

    Returns:
        bool: return 'True' for errors, 'False' otherwise.
    """
    # if the domain is renewed, for every posthook line, we check the pending
    # state: if it is '0', then we try to _delete_ the recorded hash if it is
    # up. Q: what happens if _this_ fails? A: we create a new special DEL
    # line. We then switch the state of the line to skip and then switch the
    # pending state of all the prehook lines. We then run the
    # 'process_data_prehook' function.

    errors = False
    prog.log.info1(" ++ certificate renewed again!")
    for l in group.post:
        if l.pending == '0':

            prog.log.info2(
                    " ++ will check if new cert hash matches the previous one")

            # if, for some reason, the re-renewed certificate has the same
            # hash as the previously renewed certificate, we neither want to
            # bother deleting the hash nor bother publishing that hash again
            # in 'process_data_prehook'.

            # cert: if set inside the try block, then use it in the
            # except catches.
            cert = None
            try:
                cert = certop.get_live(l.tlsa.usage,
                                            [ l.cert.live for l in group.pre ])
                prog.log.info2("  + going to use cert '{}'".format(cert))

                cert_data = certop.read_cert(cert, l.tlsa.usage)

                hash = certop.get_hash(l.tlsa.selector, l.tlsa.matching,
                                       cert_data)

                prog.log.info2("  + {}{}{} hash: {}".format(
                        l.tlsa.usage, l.tlsa.selector, l.tlsa.matching, hash))

                if hash == l.hash:
                    # what happens here is this: we have a posthook line that
                    # tells us that a previous 'new' TLSA record was published
                    # (pending state is '0'). The new live certificate has the
                    # same hash. What we want to do is keep the line as it is
                    # (do not update the time) since this new certificate has
                    # effectively already been published. Normally, if this
                    # were not the case we would delete the record (and create
                    # a delete line if this failed), switch the line state and
                    # then act as if the previous renewal never happened by
                    # switching the prehook line pending states to '0'.
                    # We would then call 'process_data_prehook' to publish new
                    # TLSA records and write new posthook lines. Since we will
                    # still do this (since there might be TLSA records that
                    # _have_ changed), we need to signify that this particular
                    # TLSA record that did not change does not need to be
                    # processed. So, we switch the tlsa state (to False) and
                    # leave the posthook line as it is.
                    prog.log.info2("  + hash has not changed; record is already up: update posthook line")

                    # 'process_data_prehook', which will be called at the
                    # end of this function, uses the tlsa records in
                    # group.target, and not the tlsa object in the DataPost
                    # objects, so let's find the matching tlsa record and
                    # change the state of that:
                    for t in group.target.tlsa:
                        if l.tlsa == t:
                            t.publish_off()
                            break
                    continue

                prog.log.info2(" ++ previous 'new' TLSA DNS record ({}) needs to be deleted: will do so after the new records are published...".format(l.tlsa.pstr()))
                l.mark_for_deletion()

            except (Except.DNSExcept, Except.InternalError) as ex:
                errors = True
                if cert:
                    prog.log.error("{}: comparing hashes failed: {}".format(
                                                            cert, ex.message))
                else:
                    prog.log.error("comparing hashes failed: {}".format(
                                                                  ex.message))

        # no matter what the pending state ('0' if the old 'new' certs
        # published a record or '1' if the old 'new' certs did not publish a
        # record) we always want to delete this line (do not write this line)
        # since the is the line for the old new cert and the certs have been
        # renewed again, EXCEPT when the new new cert matches the old new
        # cert, in which case we want to keep this line as being written,
        # which we do by continuing past this next line if so:
        l.write_state_off()
        #l.change_time("{:%s}".format(prog.timenow))

    for l in group.pre:
        l.pending_off()

    # publish TLSA records for the newly renewed certs
    errors = process_data_prehook(prog, group) or errors

    prog.log.info2("+++ deleting records previously marked for deletion...")
    for l in group.post:
        if l.mark_delete:
            try:
                delete_dane_if_up(prog, group.target.api, l.tlsa, l.hash)
            except Except.DNSSkip as ex:
                prog.log.info2("  + {}".format(ex.message))
                prog.log.info3("  + will write a delete line")
                group.add_special(
                    Prog.DataDelete(
                                group.domain, 0, l.tlsa, '1', l.time, l.hash) )
            except Except.DNSNoReturnError as ex:
                prog.log.error(ex.message)
                prog.log.info3("  + will write a delete line")
                group.add_special(
                    Prog.DataDelete(
                                group.domain, 0, l.tlsa, '1', l.time, l.hash) )
            except (Except.DNSError, Except.InternalError) as ex:
                prog.log.error(ex.message)
                prog.log.info3("  + will write a delete line")
                group.add_special(
                    Prog.DataDelete(
                                group.domain, 0, l.tlsa, '1', l.time, l.hash) )
                errors = True

    return errors

def publish_dane(prog, group):
    """Publish a DANE record.

    Called in posthook mode, for renewed or non-renewed domains, this
    function will try to publish DANE TLSA records.

    Args:
        prog (State): program internal state.
        group (DataGroup): the group of prehook and/or posthook lines.

    Returns:
        bool: return 'True' for errors, 'False' otherwise.
    """
    errors = False

    for tlsa in group.target.tlsa:
        if not tlsa.publish:
            prog.log.info1(" ++ TLSA record already up: {}".format(tlsa.pstr()))
            continue

        prog.log.info1(
                " ++ will attempt to publish TLSA DNS record: {}".format(
                                                                  tlsa.pstr()))
        pending = '0'

        # cert: if set inside the try block, then use it in the
        # except catches.
        cert = None
        try:
            cert = certop.get_live(tlsa.usage,
                                            [ l.cert.live for l in group.pre ])
            prog.log.info2("  + going to use cert '{}'".format(cert))

            cert_input = certop.read_cert(cert, tlsa.usage)

            hash = certop.get_hash(tlsa.selector, tlsa.matching,
                                        cert_input)

            prog.log.info2("  + {}{}{} hash: {}".format(
                            tlsa.usage, tlsa.selector, tlsa.matching, hash))

            # now need to use the Api object to publish a TLSA record
            apimod = import_module('alnitak.api.' + group.target.api.type.value)
            apimod.api_publish(prog, group.target.api, tlsa, hash)

        except Except.DNSSkip as ex:
            # e.g. this is likely to happen for DANE-TA(2) records, whose
            # hashes do not change as frequently. In this case we do not add
            # any posthook line
            prog.log.info2("  + record is already up; will treat all further processing as completed")
            continue
        except Except.DNSNoReturnError as ex:
            pending = '1'
            if cert:
                prog.log.error("{}: {}".format(cert, ex.message))
            else:
                prog.log.error(ex.message)
        except (Except.DNSError, Except.InternalError) as ex:
            pending = '1'
            errors = True
            if cert:
                prog.log.error("{}: {}".format(cert, ex.message))
            else:
                prog.log.error(ex.message)

        prog.log.info3(
                "  + creating posthook line with pending '{}'".format(pending))
        group.add_post( Prog.DataPost( group.domain, 0, tlsa, pending,
                                  "{:%s}".format(prog.timenow), hash) )

    if group.post:
        for l in group.pre:
            l.pending_on()
    else:
        errors2 = archive_to_live(prog, group)
        return errors or errors2

    return errors

def archive_to_live(prog, group):
    """Move dane symlinks from pointing to archive certs to back to live certs.

    Args:
        prog (State): program internal state.
        group (DataGroup): the group of prehook and/or posthook lines.

    Returns:
        bool: return 'True' for errors, 'False' otherwise.
    """
    prog.log.info1(" ++ moving dane symlinks to point from archive to live")
    errors = False

    for l in group.pre:
        prog.log.info3("  + dane: {}".format(l.cert.dane))
        if not create_symlink(prog, l.cert.dane, l.cert.live):
            errors = True
            continue

        # change the state of the line
        l.write_state_off()
        prog.log.info3("    => {} (state: {})".format(l.cert.live, l.state))

    return errors

# TODO: use me? use me!
def create_symlink(prog, symlink, to):
    """Create a symlink.

    Note that this function will try to write relative-path symlinks.

    Args:
        prog (State): program internal state.
        symlink (pathlib.Path): symlink file to create.
        to (pathilb.Path): path the symlink file points to. Can be an
            absolute or relative path: this function will handle either
            case properly.

    Returns:
        bool: return 'True' for errors, 'False' otherwise.
    """
    try:
        symlink.unlink()
    except FileNotFoundError as ex:
        pass
    except OSError as ex:
        prog.log.error("removing symlink file '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return False

    try:
        symlink.symlink_to( relative_to(symlink, to) )
    except FileExistsError as ex:
        # seeing as we deleted this file soon before this point...
        prog.log.error(
                "recreating symlink '{}': file exists".format(ex.filename))
        return False
    except OSError as ex:
        prog.log.error("recreating symlink '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return False

    return True

def relative_to(path, target):
    """Return the relative path of the input to the target path.

    For example:
        path = /a/b/d/c/Y
        target = /a/b/c/X
    Then this function will return:
        '../../c/X'

    Args:
        path (pathlib.Path):
        target (pathlib.Path):

    Returns:
        str: the path of 'path' relative to 'target'.
    """
    #   we step back through 'path' until the parent directory matches a
    #   parent directory of 'target'. We then construct the return by
    #   adding N (../) paths for the N steps back and then appending the
    #   path in 'target' that was not matched in the comparison.
    for n, p in enumerate(path.parents):
        try:
            q = target.relative_to(p)
        except ValueError:
            continue
        return "../" * n + str(q)
    return str(target)

