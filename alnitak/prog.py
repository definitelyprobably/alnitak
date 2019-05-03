
import sys
from enum import Enum
import pathlib
import datetime
import fcntl

from alnitak import exceptions as Except
from alnitak import logging
import alnitak



class State:
    """Internal program state.

    This class records data that is pertinent to the operation of the
    program. Virtuallly every function takes a State object as an
    argument since this is the central data store of things that function
    needs to operate properly.

    Class attributes are broadly classified into three groups. The first
    group is static data that controls how the program operates. The
    second group is data that controls how the program operates, but that
    can be changed with command-line flags. The last group is internal
    data that is set or read from config files or datafiles and needs to
    be shared between functions in order for them to operate.

    Attributes:
        name (str): name of the program.
        version (str): program version.
        copyright (str): copyright message.
        apis (list(str)): list of recognized API schemes, used by the
            config code to import entry points.
        tlsa_parameters_regex (str): regex that specifies a valid TLSA
            parameter.
        tlsa_domain_regex (str): regex that specifies a valid TLSA domain
            name.
        tlsa_protocol_regex (str): regex that specifies a valid TLSA
            protocol.
        ttl_min (int): minimum allowed value for the '--ttl' flag.
        ttl_max (int): maximum allowed value for the '--ttl' flag.
        timenow (datetime.datetime): UTC time right now.
        testing_mode (bool): normally 'False'. If set to 'True', then
            root-only processes are not run. This is just performing a
            chown on any files (e.g. the datafile).
        datafile (pathlib.Path): the datafile path.
        lockfile (pathlib.Path): the lock file path.
        can_lock (bool): whether the program should create a lock file.
        lock_fd (file object): the file object returned by 'open' when we
            open the lockfile.
        locked (bool): set to 'True' is the lock succeeded and the
            lockfile should be deleted at the end. If the program is run
            whilst another instance has acquired the lock, then this will
            still be 'False' and no deletion of the lockfile will take
            place: blind deletion will remove the lock when we don't want
            it to.

        setcl (SetCL): record command-line overrides of config file
            commands.
        config (pathlib.Path): the path of the config file.
        dane_directory (pathlib.Path): the path of the dane directory.
        letsencrypt_directory (pathlib.Path): the path of the Let's Encrypt
            directory (the directory the live and archive folders are in).
        letsencrypt_live_directory (pathlib.Path): the path of the live
            directory.
        ttl (int): the time-to-live value (in seconds). At least this
            number of seconds must pass since the publication of a new
            TLSA record before the old one is deleted.
        log (Log): an instance of the 'Log' class, which controls logging.
        recreate_dane (bool): set to 'True' if the '--reset' flag is
            given.

        args: the args given to argparse.
        force (bool): if the '--force' flag has been given.
        target_list (list(Target)): list of targets in the config file.
        dane_domain_directories (dict(str: list(str))): for every folder
            in the live directory, set the key to the folder name (which
            will be a domain name). The value will be a list of symlinks
            in that folder (just the name of that symlink, not its path).
        renewed_domains list((str)): set to the value of the
            'RENEWED_DOMAINS' environment parameter, if set. Otherwise
            this will be set to an empty list.
        data (Data): the Data object that records the data lines read
            from (or need to be written to) a datafile.
    """
    def __init__(self, lock=True, testing=False):
        ## program constants
        self.name = "alnitak"
        self.version = alnitak.__version__
        self.copyright = "copyright (c) K. S. Kooner, 2019, MIT License"
        self.apis = [ 'exec', 'cloudflare' ]
        self.tlsa_parameters_regex = r"[23][01][012]"
        self.tlsa_domain_regex = r"((\w[a-zA-Z0-9-]*\w|\w+)\.)+\w+"
        self.tlsa_protocol_regex = r"\w+"
        self.ttl_min = 0
        self.ttl_max = 7*24*60*60
        self.timenow = datetime.datetime.utcnow()
        self.testing_mode = testing
        self.datafile = ( pathlib.Path("/var")
                                    / self.name / str(self.name + ".data") )
        self.lockfile = pathlib.Path("/var/lock/{}.lock".format(self.name))
        self.can_lock = lock
        self.lock_fd = None
        self.locked = False

        ## program configuration data
        self.setcl = SetCL()
        self.config = pathlib.Path("/etc/{}.conf".format(self.name))
        self.dane_directory = pathlib.Path("/etc/{}/dane".format(self.name))
        self.letsencrypt_directory = pathlib.Path("/etc/letsencrypt")
        self.letsencrypt_live_directory = self.letsencrypt_directory / "live"
        self.ttl = 86400
        self.log = logging.Log(self.name, self.version, self.timenow, testing,
                               "/var/log/{}.log".format(self.name))
        self.recreate_dane = False

        ## the following are data objects filled in during operation of the
        ## program
        self.args = None
        self.force = False
        self.target_list = [ ]
        self.dane_domain_directories = { }
            # dictionary of keys that are dane domain subfolders, keyed
            # to a list of strings that are he symlinks in that subfolder.
            # For example:
            #    dane/
            #    |- x.com/
            #    |  |- link1@
            #    |  |- link2@
            #    |  |- link3@
            #    |  |- regfile1
            #    |  |- dir1/
            #    |
            #    |- y.com/
            #    |  |- link1@
            #    |  |- link2@
            #    |
            #    |- regfile1
            #
            # self.dane_domain_directories =
            #                   { 'x.com': [ 'link1', 'link2', 'link3' ],
            #                     'y.com': [ 'link1', 'link2' ] }
        self.renewed_domains = []
        self.data = Data()

    def lock(self):
        if not self.can_lock:
            return False
        try:
            self.lock_fd = open(str(self.lockfile), "w")
        except OSError as ex:
            raise Except.LockError(
                    "could not open lock file '{}': {}".format(
                                            ex.filename, ex.strerror.lower() ))
        try:
            fcntl.lockf(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            return True
        self.locked = True
        return False

    def __del__(self):
        if self.can_lock and self.locked:
            try:
                self.lockfile.unlink()
            except OSError:
                # if file removal fails, we won't really care.
                pass

    def __str__(self):
        ret = "--- SYSTEM DATA ---------------\n"
        ret += "timenow: {0} {0:%s}\n".format(self.timenow)
        ret += "logfile: {}\n".format(self.log)
        ret += "ttl: {}\n".format(self.ttl)
        ret += "renewed_domains: {}\n".format(self.renewed_domains)
        ret += "datafile: {}\n".format(self.datafile)
        ret += "dane: {}\n".format(self.dane_directory)
        ret += "letsencrypt: {}\n".format(self.letsencrypt_directory)
        ret += "live: {}\n".format(self.letsencrypt_live_directory)
        ret += "dane_domain_directories: {}".format(
                                                self.dane_domain_directories)
        for t in self.target_list:
            ret += "\n------------------\n{}".format(t)
        ret += "\n------------------\n"

        ret += "\n------------------\ndatalines:"
        #for l in self.datafile_lines:
        #    ret += "\n    =============\n{}".format(l)

        ret += "{}\n".format(self.data)

        return ret

    def make_absolute(self, path):
        p = pathlib.Path(path)
        if p.is_absolute():
            return p
        return pathlib.Path.cwd() / p

    def set_letsencrypt_directory(self, path, config=True):
        if config:
            if self.setcl.letsencrypt_directory:
                return
        else:
            self.setcl.letsencrypt_directory = True

        self.letsencrypt_directory = self.make_absolute(path)
        self.letsencrypt_live_directory = self.letsencrypt_directory / "live"

    def set_dane_directory(self, path, config=True):
        if config:
            if self.setcl.dane_directory:
                return
        else:
            self.setcl.dane_directory = True
        self.dane_directory = self.make_absolute(path)

    def set_ttl(self, ttl, config=True):
        if config:
            if self.setcl.ttl:
                return
        else:
            self.setcl.ttl = True
        self.ttl = ttl

    def set_log_level(self, level, config=True):
        if config:
            if self.setcl.level:
                return
        else:
            self.setcl.level = True

        if level == 'debug':
            self.log.set_debug_logging()
        elif level == 'verbose':
            self.log.set_verbose_logging()
        elif level == 'no':
            self.log.set_no_logging()

    def set_config_file(self, path):
        self.config = self.make_absolute(path)

class SetCL:
    """Parameters set at the command-line, overriding config equivalents.

    Attributes:
        dane_directory (bool): True if '-D' set on the command-line.
        letsencrypt_directory (bool): True if '-C' set on the command-line.
        ttl (bool): True if '-t' set on the command-line.
        level (bool): True if '-L' set on the command-line.
    """
    def __init__(self):
        self.dane_directory = False
        self.letsencrypt_directory = False
        self.ttl = False
        self.level = False

class RetVal(Enum):
    """Exit code values."""
    ok = 0
    exit_ok = 256
    exit_failure = 1
    continue_failure = 257
    config_failure = 3

class Api:
    """API scheme base class.

    Attributes:
        type (ApiType): the specific API scheme.
        domain (str): the domain the API calls will be for.
    """

    def __init__(self, type):
        self.type = type
        self.domain = None

    def set_domain(self, d):
        self.domain = d

    def __eq__(self, a):
        return (self.type == a.type and self.domain == a.domain)

    def __hash__(self):
        return hash(self.type)

class ApiCloudflare(Api):
    """The Cloudflare API scheme.

    Attributes:
        cloudflare (CloudFlare): an instance of the CloudFlare class. This
            will usually be instantiated after the corresponding module has
            been checked if it will load ok.
        zone (str): the Cloudflare zone.
        email (str): the email of the user to login as.
        key (str): the key of the user to login with.
    """

    def __init__(self, email=None, key=None):
        super().__init__(ApiType.cloudflare)
        self.cloudflare = None
        self.zone = None
        self.email = email
        self.key = key

    def copy(self):
        # this will be use in config.read to do a 'shallow' copy: we don't
        # want any global api instance to be bound to any targets since then
        # changes to the domain of that api object for every target will
        # affect every other target's api object.
        return ApiCloudflare(self.email, self.key)

    def __str__(self):
        return "    - {}\n       domain: {}\n       email: ...({})\n       key: ...({})".format(self.type, self.domain, len(self.email), len(self.key))

    def __eq__(self, a):
        return (self.type == a.type and self.domain == a.domain
                and self.zone == a.zone
                and self.email == a.email
                and self.key == a.key)

    def __hash__(self):
        return super().__hash__()

class ApiExec(Api):
    """The 'exec' API scheme

    Attributes:
        command (list(str)): the command to run (and any flags/inputs).
        uid (int): the UID to run the command as. If set to 'None' run
            as the same user as the calling user (usually 'root').
        gid (int): NOT USED. Envisioned as the GID to run the process
            under. This is instead set from the passwd info of the UID.
    """

    def __init__(self, command, uid=None, gid=None):
        super().__init__(ApiType.exec)
        self.command = command
        self.uid = uid
        self.gid = gid # NOTE: not used.

    def copy(self):
        # this will be use in config.read to do a 'shallow' copy: we don't
        # want any global api instance to be bound to any targets since then
        # changes to the domain of that api object for every target will
        # affect every other target's api object.
        return ApiExec(self.command, self.uid, self.gid)

    def __str__(self):
        return "    - {}\n       domain: {}\n       command: {} [uid: {}]".format(self.type, self.domain, self.command, self.uid, self.gid)

    def rstr(self):
        return "[{}]".format("] [".join(self.command)) + " (uid:{}) ({})".format(self.uid, self.domain)

    def __eq__(self, a):
        return (self.type == a.type and self.domain == a.domain
                and self.command == a.command
                and self.uid == a.uid
                and self.gid == a.gid)

    def __hash__(self):
        return super().__hash__()

class ApiType(Enum):
    """The API scheme."""
    exec = 'exec'
    cloudflare = 'cloudflare'

class Record:
    """Class to record the inputs to the '--print' flag.

    Attributes:
        params (str): concatenation of the tlsa usage, selector and matching
            type fields. E.g. "311", "202", etc.
        cert (str): either a X.509 certificate file, or else a Let's Encrypt
            domain where the certificate is to be located in.
    """

    def __init__(self, params, cert):
        self.params = params
        self.cert = cert

    def __eq__(self, r):
        return (self.params == r.params and self.cert == r.cert)

    def __str__(self):
        return "  params: {}\n  cert: {}".format(self.params, self.cert)

class Tlsa:
    """Class recording the data of a TLSA record.

    Attributes:
        usage (str): either '2' or '3'.
        selector (str): either '0' or '1'.
        matching (str): either '0', '1' or '2'.
        port (str): port number of the TLSA record.
        protocol (str): protocol of the TLSA record.
        domain (str): domain of the TLSA record.
        publish (bool): whether to publish the record (and create a
            posthook line) or not. Normally this is always 'True'. This
            is only ever 'False' when we have re-renewed a certificate
            whose hash to publish has not changed. In this case we do not
            need to publish a TLSA and add a posthook line since this has
            all already been done.
    """

    def __init__(self, param, port, protocol, domain):
        self.usage = param[0]
        self.selector = param[1]
        self.matching = param[2]
        self.port = port
        self.protocol = protocol
        self.domain = domain
        self.publish = True

    def __eq__(self, t):
        return ( self.usage == t.usage and self.selector == t.selector
                    and self.matching == t.matching and self.port == t.port
                    and self.protocol == t.protocol
                    and self.domain == t.domain and self.publish == t.publish )

    def params(self):
        return "{}{}{}".format(self.usage, self.selector, self.matching)

    def __str__(self):
        return "    - tlsa: {}{}{} {} {} {} [state:{}]".format(
                    self.usage, self.selector, self.matching, self.port,
                    self.protocol, self.domain, self.publish)

    def pstr(self):
        return "{}{}{} {} {} {}".format(
                    self.usage, self.selector, self.matching, self.port,
                    self.protocol, self.domain)

    def publish_off(self):
        self.publish = False

class Cert:
    """A set of corresponding live, archive and dane certificates.

    Attributes:
        dane (pathlib.Path): the absolute path of the dane certificate.
        live (pathlib.Path): the absolute path of the live certificate.
        archive (pathlib.Path): the absolute path of the archive certificate.
    """

    def __init__(self, dane, live, archive):
        self.dane = pathlib.Path(dane)
        self.live = pathlib.Path(live)
        self.archive = pathlib.Path(archive)

    def __eq__(self, c):
        return ( self.dane == c.dane and self.live == c.live
                    and self.archive == c.archive )

    def __str__(self):
        return "    - dane: {}\n      . live: {}\n      . archive: {}".format(
                                            self.dane, self.live, self.archive)

    def pstr(self):
        return "  + dane: {}\n  + live: {}\n  + archive: {}".format(
                                            self.dane, self.live, self.archive)

class Target:
    """A config file target.

    Attributes:
        domain (str): this is the section of the config file target. Its
            value should be the name of a folder in the archive directory.
        certs (list(Cert)): a list of sets of dane, live, archive certs.
        tlsa (list(Tlsa)): a list of Tlsa records.
        api (Api): A derived class of Api what stores the API scheme of
            the target.
    """

    def __init__(self, domain):
        self.domain = domain        # This is the subfolder 
        self.certs = []             # [ Cert()... ]
        self.tlsa = []              # [ Tlsa()... ]
        self.api = None             # Api()

    def __str__(self):
        #ret = "{}\n".format(self.domain)
        #for c in self.certs:
        #    ret += "{}\n    ~~~~~~~~~~~\n".format(c)
        #for t in self.tlsa:
        #    ret += "  tlsa: {}\n".format(t)
        #ret += "  api: {}".format(self.api)
        #return ret
        ret = "  + {}\n".format(self.domain)
        for c in self.certs:
            ret += "{}\n".format(c)
        for t in self.tlsa:
            ret += "{}\n".format(t)
        ret += "{}".format(self.api)
        return ret

    def __eq__(self, t):
        return (self.domain == t.domain and self.certs == t.certs
                and self.tlsa == t.tlsa and self.api == t.api)

    def matches_domain(self, str):
        if str == self.domain:
            return True
        return False

    def add_tlsa(self, t):
        self.tlsa += [ t ]

    def set_api(self, type, data):
        self.api = Api(type, data)

    def add_cert(self, dane, live, archive):
        self.certs += [ Cert(dane, live, archive) ]

class ConfigState:
    """Class to record syntax errors in the config file.

    Attributes:
        linepos (int): the line the error is on.
        errors (int): the number of errors encountered.
    """

    def __init__(self):
        self.linepos = None
        self.errors = 0

    def line(self, linepos):
        self.linepos = linepos

    def add_error(self, prog, msg):
        self.errors += 1
        if self.linepos:
            prog.log.error("config file: line {}: {}".format(self.linepos, msg))
        else:
            prog.log.error("config file: {}".format(msg))

class DataLine:
    """Base class for datalines.

    Attributes:
        type (DataLineType): the type of the line.
        domain (str): the domain of the line (e.g. 'example.com').
        lineno (int): the line number in the datafile the line was on.
            Any new lines to be written are given a line number of zero.
        state (DataLineState): whether to write the line to a new datafile
            or not.
    """

    def __init__(self, type, domain, lineno):
        self.type = type
        self.domain = domain
        self.lineno = lineno
        self.state = DataLineState.write

    def write_state_off(self):
        self.state = DataLineState.skip

class DataPre(DataLine):
    """Class recording the data in a datafile posthook line.

    Attributes:
        cert (Cert): records the dane, live and archive certificates.
        pending (str): Either '0' when written before any posthook
            operation has been made (i.e., no posthook lines also
            present), or else '1' when posthook lines also present.
    """

    def __init__(self, domain, lineno, dane, live, archive, pending):
        super().__init__(DataLineType.pre, domain, lineno)
        self.cert = Cert(dane, live, archive)
        self.pending = pending

    def __eq__(self, l):
        return ( self.type == l.type and self.domain == l.domain
                    and self.cert == l.cert and self.pending == l.pending
                    and self.state == l.state )

    def __str__(self):
        return "  + type: {}\n  + domain: {}\n  + line: {}\n{}\n  + pending: {}\n  + state: {}".format(self.type, self.domain, self.lineno, self.cert.pstr(), self.pending, self.state)

    def is_strict_eq(self, l):
        return (self.type == l.type and self.domain == l.domain
                and self.lineno == l.lineno and self.state == l.state
                and self.cert == l.cert and self.pending == l.pending)

    def pending_on(self):
        self.pending = '1'

    def pending_off(self):
        self.pending = '0'

class DataPost(DataLine):
    """Class recording the data in a datafile posthook line.

    Attributes:
        tlsa (Tlsa): TLSA record, constructed from the data line.
        pending (str): Either '0' if the TLSA record above was published,
            or else '1' if publication failed and still needs to be done.
        time (str): seconds in unix time. This is the time when the
            TLSA record was published, or else when the first attempt to
            do so was made.
        hash (str): the 'certificate data' of the record to publish or
            was published. This will be the new live certificate after
            renewal.
        mark_delete (bool): if the record above should be deleted.
            Deletion should be done after any records are published, so
            we need to mark a record for deletion before we actually do
            it.
    """

    def __init__(self, domain, lineno, tlsa, pending, time, hash):
        super().__init__(DataLineType.post, domain, lineno)
        self.tlsa = tlsa
        self.pending = pending
        self.time = time
        self.hash = hash
        self.mark_delete = False

    def __eq__(self, l):
        return ( self.type == l.type and self.domain == l.domain
                    and self.tlsa == l.tlsa and self.pending == l.pending
                    and self.hash == l.hash and self.state == l.state )

    def __str__(self):
        return "  + type: {}\n  + domain: {}\n  + line: {}\n  + tlsa: {}\n  + pending: {}\n  + time: {}\n  + hash: {}\n  + state: {}".format(self.type, self.domain, self.lineno, self.tlsa.pstr(), self.pending, self.time, self.hash, self.state)

    def is_strict_eq(self, l):
        return (self.type == l.type and self.domain == l.domain
                and self.lineno == l.lineno and self.state == l.state
                and self.tlsa == l.tlsa and self.pending == l.pending
                and self.hash == l.hash and sel.make_absolute == l.mark_delete)

    def pending_off(self):
        self.pending = '0'

    def change_time(self, time):
        self.time = time

    def mark_for_deletion(self):
        self.mark_delete = True

class DataDelete(DataLine):
    """Class recording the data in a datafile delete line.

    Attributes:
        tlsa (Tlsa): TLSA record, constructed from the data line.
        count (str): number of attempt to delete the TLSA record above.
            Starts from '1' since the failed delete that caused the delete
            line to be made counts as the first attempt. Incremented for
            every failed delete or else the line is deleted.
        time (str): seconds in unix time.
        hash (str): the 'certificate data' of the TLSA record to delete.
    """

    def __init__(self, domain, lineno, tlsa, count, time, hash):
        super().__init__(DataLineType.delete, domain, lineno)
        self.tlsa = tlsa
        self.count = count
        self.time = time
        self.hash = hash

    def __eq__(self, l):
        return ( self.type == l.type and self.domain == l.domain
                    and self.tlsa == l.tlsa and self.count == l.count
                    and self.hash == l.hash and self.state == l.state )

    def __str__(self):
        return "  + type: {}\n  + domain: {}\n  + line: {}\n  + tlsa: {}\n  + count: {}\n  + time: {}\n  + hash: {}\n  + state: {}".format(self.type, self.domain, self.lineno, self.tlsa.pstr(), self.count, self.time, self.hash, self.state)

    def is_strict_eq(self, l):
        return (self.type == l.type and self.domain == l.domain
                and self.lineno == l.lineno and self.state == l.state
                and self.tlsa == l.tlsa and self.count == l.count
                and self.hash == l.hash)

    def increment_count(self):
        c = int(self.count)
        c += 1
        self.count = str(c)

class DataLineType(Enum):
    """Type of a datafile 'data line'."""
    pre = 0
    post = 1
    delete = 2

class DataLineState(Enum):
    """Dataline state is whether the line should be written or not."""
    write = 0
    skip = 1

class DataGroup:
    """A group of datalines is a set of lines that have a common domain.

    Mathematicians: yes, set not group...

    Attributes:
        domain (str): the common domain of all the data lines.
        target (Target): the target (from the config file) that applies to
            the domain above.
        pre: (list(DataPre)): list of prehook lines.
        post: (list(DataPost)): list of posthook lines.
        special: (list(DataDelete)): list of delete lines.
    """

    def __init__(self, prog, line):
        self.domain = line.domain

        for t in prog.target_list:
            if line.domain == t.domain:
                self.target = t
                break
        else:
            self.target = None
            prog.log.warning(
                    "line {}: domain '{}' not found in config file".format(
                                                    line.lineno, line.domain))
        self.pre = []
        self.post = []
        self.special = []
        if line.type == DataLineType.pre:
            self.add_pre(line)
        elif line.type == DataLineType.post:
            self.add_post(line)
        else:
            self.add_special(line)

    def __str__(self):
        ret = " ++ group '{}'\n{}".format(self.domain, self.target)
        for l in self.post:
            ret += "\n    --- line ---------\n{}".format(l)
        for l in self.pre:
            ret += "\n    --- line ---------\n{}".format(l)
        for l in self.special:
            ret += "\n    --- line ---------\n{}".format(l)
        return ret

    def add_line(self, line):
        if line.type == DataLineType.pre:
            self.add_pre(line)
        elif line.type == DataLineType.post:
            self.add_post(line)
        else:
            self.add_special(line)

    def add_pre(self, line):
        if line in self.pre:
            return
        self.pre += [ line ]

    def add_post(self, line):
        if line in self.post:
            return
        self.post += [ line ]

    def add_special(self, line):
        if line in self.special:
            return
        self.special += [ line ]

class Data:
    """Class to record all the data in the datafile.

    Attributes:
        groups (list(DataGroup)): Lines in the datafile are grouped by
            their domain.
    """

    def __init__(self):
        self.groups = []

    def add_line(self, prog, line):
        """Line is added to either an existing group, or a new group."""
        for d in self.groups:
            if d.domain == line.domain:
                d.add_line(line)
                break
        else:
            self.groups += [ DataGroup(prog, line) ]

    def __str__(self):
        ret = " ++ printing data groups:"
        for g in self.groups:
            ret += "\n{}".format(g)
        return ret

