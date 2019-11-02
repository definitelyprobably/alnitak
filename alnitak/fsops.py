
import os
import pathlib
from datetime import datetime

from alnitak import exception
from alnitak import certops
from alnitak.prog import Error


# TODO: store the resolved live/archive/dane certs? What about making the
#       relative links wrt to the resolved paths as opposed to the unresolved
#       paths? Is this a problem with now, using the unresolved paths?
# FIXME: NOTE: when we set the api cloudflare scheme, not that the target
#               could be set to, e.g. subdomain.example.com. Here, we want
#               to login with "example.com" and NOT "subdomain.example.com":
#               we need to amend the api domain parameter.


def init_dane_directory(state):
    '''Initialize all the dane directories (DDs) given in the state object.

    For every DD, we need to create it, if not present, sanitize its
    permissions and then populate it. We will also fill in the various
    letsencrypt and dane directory keys, along with populating certificate
    locations and a few more processing-specific keys.

    This function will set the 'live_directory', 'archive_directory',
    'live_domain_directory', 'archive_domain_directory'

    Args:
        state (state.State): the state object.
    '''

    for d in state.targets:

        target = state.targets[d]

        # set letsencrypt live directories:
        target['live_directory'] = target['letsencrypt_directory'] / 'live'

        # set letsencrypt archive directories:
        target['archive_directory'] = (
                target['letsencrypt_directory'] / 'archive' )

        # set letsencrypt live domain directories:
        target['live_domain_directory'] = target['live_directory'] / d

        # set letsencrypt archive domain directories:
        target['archive_domain_directory'] = target['archive_directory'] / d

        # set dane domain directories:
        target['dane_domain_directory'] = target['dane_directory'] / d

        try:
            create_dane_directory(state, d)

            change_dane_directory_permissions(state, d)

            create_dane_domain_directory(state, d)

            populate_dane_domain_directory(
                    state, d, to_live = state.call=='init')

            # set progress:
            target['progress'] = 'prepared'

            # set prepared:
            target['prepared'] = True

        except exception.AlnitakError as ex:
            target['tainted'] = True
            if state.handler:
                state.handler.error(ex.message)


def create_dane_directory(state, domain):
    '''Create dane directory (DD) and its parents.

    If the directory is created, its mode will be set to 0700. If the
    directory already exists its mode -- whatever it is -- will not be
    changed here. The pre-existence of the diretory is not taken to be
    an error.

    Args:
        state (state.State): state object.
        domain (str): the letsencrypt domain directory name.

    Raises:
        exception.AlnitakError: if directory creation fails.
    '''
    target = state.targets[domain]

    try:
        target['dane_directory'].mkdir(mode=0o700, parents=True)
    except FileExistsError as ex:
        # Note: this catch can be removed for python 3.5+ since mkdir()
        # accepts the 'exist_ok' parameter.
        if not target['dane_directory'].is_dir():
            raise exception.AlnitakError( Error(1000,
                    "creating dane directory '{}' failed: {}".format(
                        ex.filename, ex.strerror.lower() ) ))
    except OSError as ex:
        raise exception.AlnitakError( Error(1001,
                "creating dane directory '{}' failed: {}".format(
                    ex.filename, ex.strerror.lower() ) ))


def change_dane_directory_permissions(state, domain):
    '''Change the permissions of the dane directory.

    This function will only change the mode (to 0700)  and ownership
    (to root:root) if the 'sanitize' key has been set to 'True'.

    Args:
        state (state.State): state object.
        domain (str): the letsencrypt domain directory name.

    Raises:
        exception.AlnitakError: for any failure.
    '''
    target = state.targets[domain]

    if not target['sanitize']:
        return
    try:
        target['dane_directory'].chmod(0o700)
    except OSError as ex:
        raise exception.AlnitakError( Error(1010,
                "changing permissions of dane directory '{}' failed: {}".format(
                    ex.filename, ex.strerror.lower() ) ))
    try:
        if not state.testing_mode:
            os.chown(str(target['dane_directory']), 0, 0)
    except OSError as ex:
        raise exception.AlnitakError( Error(1011,
                "changing owner of dane directory '{}' failed: {}".format(
                    ex.filename, ex.strerror.lower() ) ))


def create_dane_domain_directory(state, domain):
    '''Create a domain directory.

    Check that the live and archive domain directories exist, and then if
    so create a corresponding dane domain directory.

    Args:
        state (state.State): state object.
        domain (str): the letsencrypt domain directory name.

    Raises:
        exception.AlnitakError: for any failure.
    '''
    target = state.targets[domain]

    # check for domain in the letsencrypt live directory
    if not target['live_domain_directory'].exists():
        raise exception.AlnitakError( Error(1020,
                "target domain '{}' not found in letsencrypt live directory '{}'".format(
                    domain, target['live_domain_directory'] ) ))

    # check for domain in the letsencrypt archive directory
    if not target['archive_domain_directory'].exists():
        raise exception.AlnitakError( Error(1021,
                "target domain '{}' not found in letsencrypt archive directory '{}'".format(
                    domain, target['archive_domain_directory'] ) ))

    try:
        # create the dane domain directory
        target['dane_domain_directory'].mkdir()
    except FileExistsError as ex:
        if target['dane_domain_directory'].is_dir():
            pass
        else:
            raise exception.AlnitakError( Error(1022,
                    "creating dane domain directory '{}' failed: {}".format(
                        ex.filename, ex.strerror.lower() ) ))
    except OSError as ex:
        raise exception.AlnitakError( Error(1023,
                "creating dane domain directory '{}' failed: {}".format(
                    ex.filename, ex.strerror.lower() ) ))


def populate_dane_domain_directory(
        state, domain, to_live = False, skip_certs = False):
    '''Populate the dane domain directory (DDD) with symlinks to LE certs.

    This function will populate the DDD and also set the 'live_links' key
    to a list of symlink files found in the LE live domain directory, and
    if 'skip_certs' is not set to True will also populate the 'certs' key
    with the full paths of the various pem files.

    Args:
        state (state.State): state object.
        domain (str): the letsencrypt domain directory name.
        to_live (bool): populate with symlinks to to live certificates, or
            else to archive certificates.
        skip_certs (bool): whether to populate the 'certs' key with the full
            paths of the various pem files in the dane, live and archive
            directories.

    Raises:
        exception.AlnitakError: for any failure.
    '''
    target = state.targets[domain]

    try:
        # get a list of symlinks in the LE live folder:
        target['live_links'] = [
                f.name for f in target['live_domain_directory'].iterdir()
                        if f.is_symlink() and f.is_file() ]
    except OSError as ex:
        raise exception.AlnitakError( Error(1030,
                "getting live certs in letsencrypt live domain directory '{}' failed: {}".format(
                    ex.filename, ex.strerror.lower() ) ))

    # create files in the DDD named as the symlinks in the LDD
    for cert in target['live_links']:

        dane_file = target['dane_domain_directory'] / cert

        # set 'certs' key unless told not to
        if not skip_certs:
            set_certs(state, domain, cert, dane_file)

        # If to_live == True, then the links should be to live certificates;
        # otherwise the links should be to archive certificates
        if to_live:
            target_file = target['certs'][cert]['live']
        else:
            target_file = target['certs'][cert]['archive']

        # Now, create the DDD symlink.
        # The reason why we make several attempts at it is because if the
        # file already exists, but is not a symlink to the correct file, we
        # try to remove it and attempt the symlink creation again.
        attempts = 0
        while attempts < 3:
            attempts += 1
            try:
                dane_file.symlink_to( relative_to(dane_file, target_file) )
            except FileExistsError as ex:
                # Note: check for "not dane_file.is_dir()" rather than
                # "dane_file.is_file()" since a broken symlink returns False
                # for dane_file.is_file().
                if dane_file.is_symlink() and not dane_file.is_dir():
                    # if it is symlink to a file, read it...
                    try:
                        resolved_file = pathlib.Path(
                                os.readlink( str(dane_file) ))

                        if not resolved_file.is_absolute():
                            resolved_file = dane_file.parent / resolved_file

                        if not path_match(resolved_file, target_file):
                            try:
                                dane_file.unlink()
                            except FileNotFoundError:
                                # file doesn't exist; ok fine
                                pass
                            except OSError as ex:
                                raise exception.AlnitakError( Error(1031,
                                        "could not remove existing dane file '{}': {}".format(
                                            ex.filename, ex.strerror.lower() )))
                            continue
                    except OSError as ex:
                        raise exception.AlnitakError( Error(1032,
                                "could not resolve the symlink '{}': {}".format(
                                    ex.filename, ex.strerror.lower() ) ))
                elif not dane_file.is_dir():
                    # otherwise, as long as it's not a (symlink to a)
                    # directory, then remove it and try again...
                    try:
                        dane_file.unlink()
                    except FileNotFoundError:
                        # file doesn't exist; ok fine
                        pass
                    except OSError as ex:
                        raise exception.AlnitakError( Error(1033,
                                "could not remove existing dane file '{}': {}".format(
                                    ex.filename, ex.strerror.lower() ) ))
                    continue
                else:
                    # it it's a directory, we don't want to potentially
                    # delete a who bunch of files that could be anything;
                    # so we abort
                    raise exception.AlnitakError( Error(1034,
                            "dane cert '{}' exists as a directory; cannot continue.".format(
                                dane_file) ))
            except OSError as ex:
                raise exception.AlnitakError( Error(1035,
                        "creating symlink '{}' failed: {}".format(
                            ex.filename, ex.strerror.lower() ) ))

            break
        else:
            raise exception.AlnitakError( Error(1036,
                    "dane cert '{}' is incompatible; manual removal is required".format(
                        dane_file) ))



# TODO: docs
#
# FIXME TODO
# This function needs to handle prepare called after deploy. We will need to
# handle all the scenarios, like, for example, what to do if a record was 
# reviously published. Should we check if the domain is renewed?
def cleanup_prev_state(state, prev_state):
    '''
    '''
    # check for 'orphaned' domains:
    #  prev_state:
    #       mode: prepared, in state
    #           - do nothing
    #       mode: prepared, not in state
    #           - print warning; do nothing else
    #       mode: deployed, in state
    #           - check prev_state if published, and then delete if so
    #       mode: deployed, not in state
    #           - print warning; do nothing else
    #
    # ^ principle is that if a domain is not in the current state's config,
    #   then we have no permission to do anything about it
    #
    # FIXME: what if we have old delete records still present? Then the
    # statefile would still be around.

    if not prev_state:
        return

    for domain in prev_state.targets:

        if domain in state.targets:
            # No matter what progress is made, if a record was published,
            # let's mark it for deletion. Note: if this record matches the
            # new record when the cert data is set, that code will remove this
            # delete record when the time comes.
            for spec in prev_state.targets[domain]['records']:
                prev_record = prev_state.targets[domain]['records'][spec]
                if prev_record['new']['published']:
                    state.create_delete(domain, spec, prev_state=prev_state)

                for delete in prev_record['delete']:
                    state.targets[domain]['records'][spec]['delete'][
                                    delete] = prev_record['delete'][delete]
        else:
            # TODO: cleanup these messages
            if state.handler:
                if target['progress'] == 'prepared':
                    state.handler.warning("domain '{}' is orphaned: it is no longer present in the config settings; no action is needed".format(domain))
                elif target['progress'] == 'deployed':

                    message = ''
                    for spec in target['records']:
                        record = target['records'][spec]
                        if record['new']['published']:
                            message += '\n  - {}'.format(
                                    state.tlsa_record_formatted(domain, spec))

                            message += '\n  - {}'.format(
                                state.tlsa_record_formatted(domain,spec,False))

                    if message:
                        state.handler.warning("domain '{}' is orphaned: it is no longer present in the config settings; the following records were published:{}".format(domain, message))
                    else:
                        state.handler.warning("domain '{}' is orphaned: it is no longer present in the config settings; no action is needed".format(domain))
                else:
                    state.handler.internal_error(
                            "target progress '{}' is invalid".format(
                                target['progress'] ))


# TODO: docs
def set_renewed(state):
    '''
    '''
    for d in state.targets:
        target = state.targets[d]

        # only want to add one domain to state.renewed_domains, but we need
        # to loop over all the certs in target.certs so that the renew values
        # are set. We will remember if the domain has already been added with
        # this bool, so that we don't add it multiple times
        added_to_renewed = False

        for cert in target['certs']:

            # get the current live certificate
            curr_live = target['live_domain_directory'] / cert

            if not curr_live.is_symlink():
                raise exception.AlnitakError( Error(1040,
                        "live certificate '{}' is not a symlink".format(
                            curr_live ) ))

            if curr_live.is_dir():
                raise exception.AlnitakError( Error(1041,
                        "live certificate '{}' does not point to a file".format(
                            curr_live ) ))

            # get current archive certificate
            try:
                curr_archive = resolve(curr_live)

                # resolved archive must be in LE dir:
                if ( curr_archive.parent !=
                            resolve(target['archive_domain_directory']) ):
                    raise exception.AlnitakError( Error(1042,
                        "archive cert '{}' not in letsencrypt directory '{}'".format(
                            curr_archive, target['archive_domain_directory'] )))


                # if current (resolved) archive does not match the (resolved)
                # archive in the program state, then we interpret it as
                # renewed.
                # what if only some of the certs have been renewed? That is,
                # what if, say, cert.pem points to a new archive file, but
                # chain.pem does not? Potentially, this may cause TLSA
                # records to be created that are identical to previous
                # ones. Since this will already be handled, we will NOT
                # point this as an error here. As long as ONE cert is
                # different, we will take the whole domain to have been
                # renewed.
                if curr_archive != resolve(target['certs'][cert]['archive']):
                    # if the current archive cert is already set in 'renew',
                    # then renewal occurred before and has not been renewed
                    # again; we do not need to set renewed_domains
                    if str(target['certs'][cert]['renew']) != str(
                                        target['archive_domain_directory']
                                                        / curr_archive.name):
                        target['certs'][cert]['renew'] = (
                                    target['archive_domain_directory']
                                                        / curr_archive.name )
                        if not added_to_renewed:
                            state.renewed_domains += [ d ]
                            added_to_renewed = True

            except exception.AlnitakResolveError as ex:
                raise exception.AlnitakError( Error(1043,
                        "could not resolve '{}': {}".format(
                            ex.filename, ex.strerror.lower() ) ))


# TODO: docs
def process_deployed(state):
    '''
    '''

    for d in state.targets:
        target = state.targets[d]

        if target['tainted']:
            # do not process
            continue

        try:
            if target['progress'] == 'unprepared':
                # <renew>
                # alnitak deploy
                if d in state.renewed_domains:
                    set_new_cert_data(state, d)
                    # don't bother creating prev cert data
                    publish_records(state, d)
                    move_symlinks(state, d)

                #
                # alnitak deploy
                else:
                    # here, nothing is needed. Likely we got here by the
                    # domain not being renewed on the first deploy mode call,
                    # so the dane links were moved back to live, and now we've
                    # done another renewal (without preparation) and the
                    # domain was not in the list of renewed domains. Nothing
                    # needs to be done.
                    pass

            elif target['progress'] == 'prepared':
                # alnitak prepare
                # <renew>
                # alnitak deploy
                if d in state.renewed_domains:
                    set_cert_data(state, d)
                    publish_records(state, d)
                    move_symlinks(state, d)

                # alnitak prepare
                # alnitak deploy
                else:
                    populate_dane_domain_directory(
                                state, d, to_live=True, skip_certs=True)
                    target['progress'] = 'unprepared'

            elif target['progress'] == 'deployed':
                # [alnitak prepare]  (possibly run)
                # <renew>
                # alnitak deploy
                # alnitak deploy
                if d in state.renewed_domains:
                    set_cert_data(state, d, update=True)
                    publish_records(state, d)
                    move_symlinks(state, d)

                # [alnitak prepare]  (possibly run)
                # alnitak deploy
                # alnitak deploy
                else:
                    publish_records(state, d)
                    delete_records(state, d)
                    move_symlinks(state, d)

            else:
                if state.handler:
                    state.handler.internal_error(
                            "target progress '{}' invalid".format(
                                target['progress'] ))

        except exception.AlnitakError as ex:
            # FIXME: should I taint?
            #target['tainted'] = True
            if state.handler:
                state.handler.error(ex.message)


# TODO: docs
def set_cert_data(state, domain, update=False):
    '''
    '''
    # Note: always call prev before new since new needs to check if its
    # cert data is the same as the prev cert data
    set_prev_cert_data(state, domain, update)
    set_new_cert_data(state, domain, update)

# TODO: docs
def set_prev_cert_data(state, domain, update=False):
    '''
    '''
    # we always want to overwrite contents of 'prev' unless:
    #   1. update == True
    #       only when deploy mode called in progress state 'deployed'. We
    #       assume the caller always runs prepare, so this is not a mistake,
    #       rather this is the program called again by some post-hook.
    #       Here, what we do is check that cert_data has not changed. If it
    #       has, then we overwrite prev, otherwise we just leave it alone.
    #   2. if cert_data matches new cert_data, we blank prev; otherwise, we
    #       write new cert data.
    for spec in state.targets[domain]['records']:
        params = state.targets[domain]['records'][spec]['params']
        pem = certops.get_pem(state, domain, params['usage'])
        cert_data = certops.get_cert_data(params, pem)

        # check if cert_data is in 'new':
        #if state.targets[domain]['records'][spec]['new']:
        #    if (state.targets[domain]['records'][spec]['new']['data'] ==
        #            cert_data):
        #        state.blank_prev_record(domain, spec)
        #        continue

        # if update is set, we check if data is already present, and if so we
        # won't overwrite
        if state.targets[domain]['records'][spec]['prev']:
            if (state.targets[domain]['records'][spec]['prev']['data'] ==
                    cert_data):
                if update:
                    continue

        state.set_prev_record(domain, spec, cert_data)

# TODO: docs
def set_new_cert_data(state, domain, update=False):
    '''
    '''
    # similar to set_prev_cert_data, we always want to overwrite the contents
    # of 'new' unless:
    #   1. update == True
    #       only when deploy mode called in progress state 'deployed'. We
    #       assume the caller always runs prepare, so this is not a mistake,
    #       rather this is the program called again by some post-hook.
    #       Here, what we do is check that cert_data has not changed. If it
    #       has, then we overwrite prev, otherwise we just leave it alone.
    #   2. if cert_data matches new cert_data, we blank prev; otherwise, we
    #       write new cert data.
    for spec in state.targets[domain]['records']:
        params = state.targets[domain]['records'][spec]['params']
        pem = certops.get_pem(state, domain, params['usage'], use_renew = True)
        cert_data = certops.get_cert_data(params, pem)

        # check if data exists in prev and if so remove it
        if (state.targets[domain]['records'][spec]['prev'] and
                state.targets[domain]['records'][spec]['prev']['data'] ==
                    cert_data):
            state.blank_prev_record(domain, spec)

        # check if data exists in delete and if so remove it
        state.remove_delete_record(domain, spec, cert_data)

        if update:
            # data is the same, no need to do anything
            if state.targets[domain]['records'][spec]['new']:
                if (state.targets[domain]['records'][spec]['new']['data'] ==
                        cert_data):
                    continue

            # data was published, we need to set the 'update' field so we can
            # process this later...
            if state.targets[domain]['records'][spec]['new']:
                if state.targets[domain]['records'][spec]['new']['published']:
                    state.targets[domain]['records'][spec]['new'] = {
                            'data': cert_data,
                            'published': False,
                            'is_up': False,
                            'update': state.targets[
                                domain]['records'][spec]['new']['data'],
                            'time': int( '{:%s}'.format(datetime.utcnow()) )
                            }
                    continue

        # otherwise always overwrite
        state.targets[domain]['records'][spec]['new'] = {
                'data': cert_data,
                'published': False,
                'is_up': False,
                'update': None,
                'time': int( '{:%s}'.format(datetime.utcnow()) )
                }


# TODO: docs
def publish_records(state, domain):
    '''
    '''
    target = state.targets[domain]

    if target['api']['type'] == 'cloudflare':
        from alnitak.api.cloudflare import api_publish
    else:
        from alnitak.api.exec import api_publish

    for spec in target['records']:
        if target['records'][spec]['new']['published']:
            continue

        try:
            api_publish(state, domain, spec)

        except exception.AlnitakError as ex:
            # Note: don't set tainted since publish errors, even something
            # like file not found errors, should not stop future calls from
            # processing the record.
            if state.handler:
                state.handler.error(ex.message)

# TODO: docs
def delete_records(state, domain):
    '''
    '''
    target = state.targets[domain]

    if target['api']['type'] == 'cloudflare':
        from alnitak.api.cloudflare import api_read_delete
    else:
        from alnitak.api.exec import api_read_delete

    for spec in target['records']:
        # if record not published, don't delete
        if not target['records'][spec]['new']['published']:
            continue

        # if ttl hasn't passed, don't delete
        if ( int( '{:%s}'.format(datetime.utcnow()) ) <
                int(target['ttl']) +
                int(target['records'][spec]['new']['time']) ):
            continue

        # if record already processed, then is_up will be set to true;
        # don't do anything here. If delete failed before, then it will
        # have been moved to delete, and 'process_deletes' will handle it
        if target['records'][spec]['new']['is_up']:
            continue

        try:
            api_read_delete(state, domain, spec)
        except exception.AlnitakError as ex:
            # delete failed, so move data from prev to delete
            state.create_delete(domain, spec)
            state.blank_prev_record(domain, spec)

            # Note: don't set tainted since publish errors, even something
            # like file not found errors, should not stop future calls from
            # processing the record.
            if state.handler:
                state.handler.error(ex.message)


# TODO: docs
def move_symlinks(state, domain):
    '''
    '''
    target = state.targets[domain]

    for spec in target['records']:
        if not target['records'][spec]['new']['is_up']:
            break
    else:
        if target['prepared']:
            populate_dane_domain_directory(
                        state, domain, to_live=True, skip_certs=True)
        target['progress'] = 'unprepared'
        return
    target['progress'] = 'deployed'


# TODO: docs
def process_deletes(state):
    '''
    '''
    for domain in state.targets:
        target = state.targets[domain]

        if target['api']['type'] == 'cloudflare':
            from alnitak.api.cloudflare import api_read_delete
        else:
            from alnitak.api.exec import api_read_delete

        for spec in target['records']:
            record = target['records'][spec]

            for data in record['delete']:
                try:
                    api_read_delete(state, domain, spec, data)
                except exception.AlnitakError as ex:
                    # Note: don't set tainted since delete errors, should
                    # not stop future calls from processing the record.
                    if state.handler:
                        state.handler.error(ex.message)


def relative_to(base, target):
    '''Return the relative path of the target relative to the base path.

    For example:
        base = /a/b/d/c/Y
        target = /a/b/c/X
    Then this function will return:
        '../../c/X'

    Note: base and target are assumed to both be not directories.

    Args:
        base (pathlib.Path): the base path to output relative to.
        target (pathlib.Path): the path to act on.

    Returns:
        str: the path of 'target' relative to 'base'.
    '''
    #   we step back through 'base' until the parent directory matches a
    #   parent directory of 'target'. We then construct the return by
    #   adding N (../) paths for the N steps back and then appending the
    #   path in 'target' that was not matched in the comparison.
    for n, p in enumerate( pathlib.Path(base).parents):
        try:
            q = pathlib.Path(target).relative_to(p)
        except ValueError:
            continue
        return "../" * n + str(q)
    return str(target)

def path_match(path1, path2):
    '''Test if path1 and path2 resolve to the same file

    Args:
        path1 (pathlib.Path): object to compare.
        path2 (pathlib.Path): object to compare.

    Returns:
        bool: True if path1 and path2 resolve to the same file, False
            otherwise.

    Raises:
        exception.AlnitakResolveError: if an element of either path1 or path2
            does not exist on the system, or if an infinite loop is
            encountered within path1 or path2.
    '''
    return (resolve(path1.parent) / path1.name
                == resolve(path2.parent) / path2.name)

def set_certs(state, domain, cert, dane_file):
    '''Populate the 'certs' key.

    Args:
        state (state.State): the state object.
        domain (str): the letsencrypt domain directory name.
        cert (str): the pem certificate filename to fill in data for.
        dane_file (pathlib.Path): the full path of the dane certificate file.

    Raises:
        exception.AlnitakError: for any failure.
    '''
    target = state.targets[domain]

    # if target['certs'][cert] has not already been created, we will initialize
    # it now. We do not include the code that sets the 'archive' keys in this
    # 'if' block because these may need updating on subsequent calls to this
    # function (e.g., in some 'deploy' mode calls), while 'dane' and 'live'
    # will never be needed to be updated. The 'renew' key will not be updated
    # here, so we'll leave that inside the 'if' block so that it doesn't get
    # blanked again on subsequent calls.
    # The 'archive' key we will set to 'None' before being updated soon so
    # that all keys are present even if something raises an exception.
    if cert not in target['certs']:
        target['certs'][cert] = {}
        target['certs'][cert]['archive'] = None
        target['certs'][cert]['renew'] = None
        target['certs'][cert]['dane'] = dane_file
        target['certs'][cert]['live'] = target['live_domain_directory'] / cert

    try:
        archive_resolved = resolve(target['certs'][cert]['live'])
    except exception.AlnitakResolveError as ex:
        raise exception.AlnitakError( Error(1050,
                "live cert '{}' could not be resolved: {}".format(
                    ex.filename, ex.strerror.lower() ) ))

    try:
        if ( archive_resolved.parent !=
                resolve(target['archive_domain_directory']) ):
            raise exception.AlnitakError( Error(1051,
                    "archive cert '{}' not in letsencrypt archive directory '{}'".format(
                        target['archive_domain_directory'] ) ))
    except exception.AlnitakResolveError as ex:
        raise exception.AlnitakError( Error(1052,
                "archive domain directory '{}' could not be resolved: {}".format(
                    ex.filename, ex.strerror.lower() ) ))

    # set it as follows so that we respect the path structure given
    # and not resolve any symlinks in the archive domain directory, if
    # there are any
    target['certs'][cert]['archive'] = ( target['archive_domain_directory'] /
                                            archive_resolved.name )

def resolve(path):
    '''Compatibility function for pathlib.Path.resolve()

    Pathlib versions before 3.6 did not accept a 'strict' argument, but
    behaved as if 'strict' was set to 'True'. From python 3.6 onwards, the
    resolve method behaved by setting 'strict' to 'False' by default, and
    thus we must set 'strict' to 'True' explicitly.

    Args:
        path (pathlib.Path): the path object to resolve

    Returns:
        pathlib.Path: the resolved path

    Raises:
        exception.AlnitakResolveError: pathlib.Path.resolve can throw
            either FileNotFoundError if an element of 'path' does not exist
            on the system, or RuntimeError if an infinite loop is
            encountered. We will repackage either exception into
            AlnitakResolveError so that internal data is presented
            consistently (i.e, self.filename and self.strerror are guaranteed
            to exist).
    '''
    try:
        try:
            return path.resolve(strict=True)
        except TypeError:
            pass
        return path.resolve()
    except FileNotFoundError as ex:
        raise exception.AlnitakResolveError(ex.filename, ex.strerror)
    except RuntimeError as ex:
        raise exception.AlnitakResolveError(path, str(ex))

