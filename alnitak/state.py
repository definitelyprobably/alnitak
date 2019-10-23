
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

    def create_target(self, domain):
        if domain in self.targets:
            return False # FIXME return or raise?
        self.targets[domain] = {
                'records': {},
                'api': {},
                    # {
                    #   'exec': {
                    #       'command': [ 'bin', '--flag0', '--flag1' ],
                    #       'uid': 0,
                    #       'gid': 0,
                    #       },
                    #   'cloudflare': {
                    #       'version': 4,
                    #       'object': None, # store the cloudflare API object
                    #       'zone': None,
                    #       'email': None,
                    #       'key': None,
                    #       }
                    # }
                'dane_directory': Path('/etc/alnitak/dane'),
                'dane_domain_directory': None,
                    # set in init
                'dane_directory_processed': False,
                'dane_directory_created': False,
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
                'sanitize': False,
                    # enforce DD permissions to be correct.
                'certs': {}
                    # e.g. { 'cert.pem': { 'live': '...', 'archive': '...',
                    #           'dane': '...', renew: '...' }, ... }
            }
        return True


    def create_record(self, domain, usage, selector, matching_type, port,
                      protocol, record_domain=None):
        if not record_domain:
            record_domain = domain
        spec = "{}{}{}".format(usage, selector, matching_type)
        self.targets[domain]['records'][spec] = {
                'params': {
                    'usage': usage,
                    'selector': selector,
                    'matching_type': matching_type
                    },
                'port': port,
                'protocol': protocol,
                'domain': record_domain,
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

    def create_delete(self, domain, spec, use_new = False, prev = None):
        if prev:
            data = prev.targets[domain]['records'][spec]['new']['data']
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

    # XXX
    def debug_cut_paths(self, p):
        if not p:
            return p
        if len(p.parents) > 4:
            return "...{}".format( p.relative_to(list(p.parents)[4]) )
        else:
            return p

    def debug_print(self):
        print('~~~~~~ state ~~~~~~~~~~~~~~~~~~~~~')
        for d in self.targets:
            target = self.targets[d]
            print()
            print(d)
            print('-'*len(d))
            print('  dane directory:           {}'.format(self.debug_cut_paths(target['dane_directory'])))
            print('      + processed: {}, created: {}'.format(str(target['dane_directory_processed']), str(target['dane_directory_created'])))
            print('      + sanitize: {}'.format(str(target['sanitize'])))
            print('  dane domain directory:    {}'.format(self.debug_cut_paths(target['dane_domain_directory'])))
            print('  letsencrypt directory:    {}'.format(self.debug_cut_paths(target['letsencrypt_directory'])))
            print('  live directory:           {}'.format(self.debug_cut_paths(target['live_directory'])))
            print('  live domain directory:    {}'.format(self.debug_cut_paths(target['live_domain_directory'])))
            print('  archive directory:        {}'.format(self.debug_cut_paths(target['archive_directory'])))
            print('  archive domain directory: {}'.format(self.debug_cut_paths(target['archive_domain_directory'])))
            print('  live links: {}'.format(str(target['live_links'])))
            print('  ttl: {}'.format(str(target['ttl'])))
            print('  tainted: {}'.format(str(target['tainted'])))
            print('  progress: {}'.format(str(target['progress'])))
            print('  certs:')
            for c in target['certs']:
                print('    {}'.format(str(c)))
                print('        + dane:    {}'.format(self.debug_cut_paths(target['certs'][c]['dane'])))
                print('        + live:    {}'.format(self.debug_cut_paths(target['certs'][c]['live'])))
                print('        + archive: {}'.format(self.debug_cut_paths(target['certs'][c]['archive'])))
                print('        + renew:   {}'.format(self.debug_cut_paths(target['certs'][c]['renew'])))
            for r in target['records']:
                print('  records:')
                print('      {}'.format(r))
                print('        usage: {}  selector: {}  matching_type: {}'.format(str(target['records'][r]['params']['usage']), str(target['records'][r]['params']['selector']), str(target['records'][r]['params']['matching_type'])))
                print('        port: {}  protocol: {}  domain: {}'.format(str(target['records'][r]['port']), str(target['records'][r]['protocol']), str(target['records'][r]['domain'])))
                print('        delete:')
                if target['records'][r]['delete']:
                    for dr in target['records'][r]['delete']:
                        delrec = target['records'][r]['delete'][dr]
                        print('            {}'.format(dr))
                        print('                data: {}...{}'.format(str(delrec['data'][:10]), str(delrec['data'][-10:])))
                        print('        time: {}'.format(str(delrec['time'])))
                else:
                    print('            None')
                print('        new:')
                print('            data: {}...{}'.format(str(target['records'][r]['new']['data'][:10]), str(target['records'][r]['new']['data'][-10:])))
                print('            published: {}'.format(str(target['records'][r]['new']['published'])))
                print('            is_up: {}'.format(str(target['records'][r]['new']['is_up'])))
                print('            update: {}'.format(str(target['records'][r]['new']['update'])))
                print('            time: {}'.format(str(target['records'][r]['new']['time'])))
                print('        prev:')
                print('            data: {}...{}'.format(str(target['records'][r]['prev']['data'][:10]), str(target['records'][r]['prev']['data'][-10:])))
                print('            time: {}'.format(str(target['records'][r]['prev']['time'])))
                if target['api']['type'] == 'exec':
                    print('  api:')
                    print('      type: exec')
                    print('      command'.format(str(target['api']['command'])))
                    print('      uid: {}  gid: {}'.format(str(target['api']['uid']), str(target['api']['gid'])))
                elif target['api']['type'] == 'cloudflare':
                    print('  api:')
                    print('      api: cloudflare')
                    print('      version: {}'.format(str(target['api']['version'])))
                    print('      zone: {}'.format(str(target['api']['zone'])))
                    print('      email: {}'.format(str(target['api']['email'])))
                    print('      key: {}'.format(str(target['api']['key'])))
                else:
                    print('  <unknown> {}'.format(target['api']))





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




# FIXME: message could be a list of error messages.
#           if type(message) is list:
#               for i in message:
#                   print(i)
#           else:
#               print(message)
class PrintHandler:
    def __init__(self):
        self.progname = 'alnitak' # FIXME

    def warning(self, message): # FIXME
        print("{}: warning: {}".format(self.progname, message), file=sys.stderr)

    def error(self, message): # FIXME
        print("{}: error: {}".format(self.progname, message), file=sys.stderr)

    def internal_error(self, message): # FIXME
        print("{}: internal error: {}".format(self.progname, message),
              file=sys.stderr)


class Prog:
    '''
    The Prog class records information pertinent to the frontend operations
    of the program.
    '''
    pass





class RetVal(Enum):
    """Exit code values."""
    ok = 0
    exit_ok = 256
    exit_failure = 1
    continue_failure = 257
    config_failure = 3











