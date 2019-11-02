
import sys
from pathlib import Path
from datetime import datetime # XXX
from enum import Enum # XXX


# The 'configuration data' of the program, is the data that tells the program
# what to do. Specifically, what TLSA records to publish, where the Let's
# Encrypt certificates are located, where to create the dane directory etc.

class State:
    '''
    The program 'state' records those parameters of operation that allow
    resumption of operation between program calls.

    config: data read from the configuration file(s).
    cert_data: data on the Let's Encrypt certificates.
    '''
    def __init__(self):
        self.renewed_domains = []
        self.targets = {}
        self.call = None # the program mode; e.g. 'prepare', 'deploy' etc.
        self.handler = None
        self.log_level = None # FIXME set to 'normal'? 'debug'? an enum?
        self.testing_mode = False
            # in testing mode, skip the dane directory chown to root

    # FIXME: write the rest of the call options
    def set_call_init(self):
        self.call = 'init'

    # FIXME: write the rest of the call options
    def set_call_prepare(self):
        self.call = 'prepare'

    # FIXME: write the rest of the call options
    def set_call_deploy(self):
        self.call = 'deploy'

    # TODO: use me!
    def set_progress_prepared(self, domain):
        self.targets[domain]['progress'] = 'prepared'

    # TODO: use me!
    def set_progress_deployed(self, domain):
        self.targets[domain]['progress'] = 'deployed'

    # TODO: use me!
    def set_progress_unprepared(self, domain):
        self.targets[domain]['progress'] = 'unprepared'

    # TODO: use me!
    def set_dane_directory(self, domain, path):
        self.targets[domain]['dane_directory'] = path

    # TODO: use me!
    def set_letsencrypt_directory(self, domain, path):
        self.targets[domain]['letsencrypt_directory'] = path

    def set_sanitize(self, domain):
        self.targets[domain]['sanitize'] = True

    def set_ttl(self, domain, ttl):
        self.targets[domain]['ttl'] = ttl

    def create_target(self, domain):
        if domain in self.targets:
            return False # FIXME return or raise?
        self.targets[domain] = {
                'records': {},
                'api': {},
                    # {
                    #   'type': 'exec'
                    #   'command': [ 'bin', '--flag0', '--flag1' ],
                    #   'uid': 0,
                    #   'gid': 0,
                    # }
                    #   OR
                    # {
                    #   'type': 'cloudflare'
                    #   'version': 4,
                    #   'object': None, # store the cloudflare API object
                    #   'zone': None,
                    #   'email': None,
                    #   'key': None,
                    # }
                'dane_directory': Path('/etc/alnitak/dane'),
                'dane_domain_directory': None,
                    # set in init
                'letsencrypt_directory': Path('/etc/letsencrypt'),
                'live_directory': None,
                    # set in init
                'live_domain_directory': None,
                    # set in init
                'archive_directory': None,
                    # set in init
                'archive_domain_directory': None,
                    # set in init
                'live_links': [],
                    # names of symlinks in live domain directory
                'ttl': 86400,
                'tainted': False,
                    # True if errors exist so that the target should
                    # not be further processed. This should also be
                    # read to see how the frontend should exit.
                'progress': 'unprepared',
                'prepared': False,
                    # if we run prepare, then set this to True. If we run
                    # deploy without preparation, then we won't have moved
                    # the live symlinks to archive certs, so when moving
                    # the symlinks back, we have nothing to do.
                'sanitize': False,
                    # enforce DD permissions to be correct.
                'certs': {}
                    # e.g. { 'cert.pem': { 'live': '...', 'archive': '...',
                    #           'dane': '...', renew: '...' }, ... }
            }
        return True


    def create_record(self, domain, usage, selector, matching_type, port,
                      protocol, record_domain=None):
        if record_domain:
            rdomain = record_domain
        else:
            rdomain = domain
        spec = "{}{}{}._{}._{}.{}".format(
                    usage, selector, matching_type, port, protocol, rdomain)
        self.targets[domain]['records'][spec] = {
                'params': {
                    'usage': usage,
                    'selector': selector,
                    'matching_type': matching_type
                    },
                'port': port,
                'protocol': protocol,
                'domain': rdomain,
                'delete': {},
                'prev': {
                    'data': None,
                    'time': 0
                    },
                'new': {
                    'data': None,
                    'published': False,
                    'is_up': False,
                    'update': None,
                    'time': 0
                    }
                }

    # FIXME: is use_new ever used?
    def create_delete(self, domain, spec, use_new = False, prev_state = None):
        if prev_state:
            data = prev_state.targets[domain]['records'][spec]['new']['data']
            self.targets[domain]['records'][spec]['delete'][data] = {
                    'data': data,
                    'time': int('{:%s}'.format(datetime.utcnow()))
                    }
        else:
            record = self.targets[domain]['records'][spec]
            if use_new:
                record['delete'][record['new']['data']] = {
                        'data': record['new']['data'],
                        'time': int( '{:%s}'.format(datetime.utcnow()) )
                        }
            else:
                # only move prev record if it exists. It won't exist for, e.g.
                # 2xx records.
                if record['prev']['data']:
                    record['delete'][record['prev']['data']] = {
                            'data': record['prev']['data'],
                            'time': int( '{:%s}'.format(datetime.utcnow()) )
                            }

    def set_prev_record(self, domain, spec, data):
        self.targets[domain]['records'][spec]['prev'] = {
                'data': data,
                'time': int( '{:%s}'.format(datetime.utcnow()) )
                }

    def blank_prev_record(self, domain, spec):
        self.targets[domain]['records'][spec]['prev'] = {
                'data': None,
                'time': 0
                }

    def remove_delete_record(self, domain, spec, data):
        try:
            if self.targets[domain]['records'][spec]['delete']:
                del(self.targets[domain]['records'][spec]['delete'][data])
        except KeyError:
            pass

    def create_api_exec(self, domain, command, uid=0):
        self.targets[domain]['api'] = {
                'type': 'exec',
                'command': command,
                'uid': int(uid),
                'gid': int(uid), # FIXME
                }

    def create_api_cloudflare(self, domain, version=4):
        self.targets[domain]['api'] = {
                'type': 'cloudflare',
                'version': version,
                'object': None,
                'zone': None,
                'email': None,
                'key': None
                }

    def tlsa_record_formatted(self, domain, spec, use_new = True):
        '''
        '''
        record = self.targets[domain]['records'][spec]
        if use_new:
            data = record['new']['data']
        else:
            data = record['prev']['data']
        return "_{}._{}.{}  {} {} {}  {}".format(
                record['port'],
                record['protocol'],
                record['domain'],
                record['params']['usage'],
                record['params']['selector'],
                record['params']['matching_type'],
                data)


    # FIXME: am I used? Otherwise delete me!
    # FIXME: keys may be outdated
    def set_new_data(
            self, domain, spec, data, published = False, explicitly = False):
        '''
        '''
        record = self.targets[domain]['records']

        if data in record[spec]['data_new']:
            # if new data matches an entry that's already in data_new,
            # then we have nothing to do since the new record is no different
            # to a previous one, and that one takes precedence in terms of
            # processing.
            return

        # if there are new records (in data_new), we need to move them
        # to data_delete.
        for d in record[spec]['data_new']:
            # Note: d should never be in both data_delete and data_new, which
            # is ensured by the code above.
            if record[spec]['data_new'][d]['published']:
                record[spec]['data_delete'][d] = record[spec]['data_new'][d]

        record[spec]['data_new'] = {
                data: { 'published': published,
                        'explicitly': explicitly,
                        'time': int( '{:%s}'.format(datetime.utcnow()) ) } }


    # FIXME: am I used? Otherwise delete me!
    # FIXME: keys may be outdated
    def set_old_data(self, domain, spec, data):
        '''
        '''
        record = self.targets[domain]['records']

        if data not in record[spec]['data_new']:
            record[spec]['data_prev'][data] = { 'published': True,
                                                'explicitly': False,
                                                'time': None }



class RetVal(Enum):
    """Exit code values."""
    ok = 0
    exit_ok = 256
    exit_failure = 1
    continue_failure = 257
    config_failure = 3

