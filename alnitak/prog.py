import sys
from enum import Enum
import pathlib
import logging
import datetime

import alnitak


class State:
    def __init__(self, lock=True, testing=False):
        ## program constants
        self.name = "alnitak"
        self.version = alnitak.__version__
        self.copyright = "copyright (c) Karta Kooner, 2019, MIT License"
        self.tlsa_parameters_regex = "[23][01][012]"
        self.tlsa_domain_regex = r"((\w[a-zA-Z0-9-]*\w|\w+)\.)+\w+"
        self.tlsa_protocol_regex = r"\w+"
        self.timenow = datetime.datetime.now()
        self.ttl_min = 0 # FIXME: leave me? Set to something like 60?
        self.testing_mode = testing

        ## program configuration data
        self.config = pathlib.Path("/etc/{}.conf".format(self.name))
        self.dane_directory = pathlib.Path("/etc/{}/dane".format(self.name))
        self.letsencrypt_directory = pathlib.Path("/etc/letsencrypt")
        self.letsencrypt_live_directory = self.letsencrypt_directory / "live"
        self.datafile = ( pathlib.Path("/var")
                                    / self.name / str(self.name + ".data") )
        self.ttl = 86400
        self.log = Log(file="/var/log/{}.log".format(self.name), name=self.name)
        self.lockfile = pathlib.Path("/run/lock/{}.lock".format(self.name))
        self.can_lock = lock
        self.locked = False
        self.recreate_dane = False
        self.args = None

        ## the following are data objects filled in during operation of the
        ## program

        # list of Target objects
        self.target_list = [ ]

        # dictionary of keys that are dane domain subfolders, keyed to a list
        # of strings that are he symlinks in that subfolder. E.g.:
        #    $ ls dane/
        #      x.com/  y.com/  regfile1
        #
        #    $ ls dane/x.com/
        #      link1@   link2@  link3@  regfile1  dir1/
        #
        #    $ ls dane/y.com/
        #      link1@   link2@
        #
        # self.dane_domain_directories =
        #                       { 'x.com': [ 'link1', 'link2', 'link3' ],
        #                         'y.com': [ 'link1', 'link2' ] }
        self.dane_domain_directories = { }

        # list of domains in the RENEWED_DOMAINS environment parameter
        self.renewed_domains = []

        # when posthook mode reads a datafile, store the data here
        self.datafile_lines = []

        # Data object filled in from the datafile
        self.data = Data()

        # Let's create a lockfile
        if self.can_lock:
            try:
                with open(str(self.lockfile), "x") as lock:
                    self.locked = True
            except FileExistsError:
                sys.exit(100)
            except OSError:
                sys.exit(101)

    def __del__(self):
        if self.can_lock and self.locked:
            try:
                self.lockfile.unlink()
                # FIXME the above is problematic
            except FileNotFoundError:
                sys.exit(110)
            except OSError:
                sys.exit(111)

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
        for l in self.datafile_lines:
            ret += "\n    =============\n{}".format(l)

        ret += "{}\n".format(self.data)

        return ret

    def init_logging(self, args):
        self.args = args
        return self.log.init(self.name, self.version, self.timenow)

    def make_absolute(self, path):
        p = pathlib.Path(path)
        if p.is_absolute():
            return p
        return pathlib.Path.cwd() / p

    def set_letsencrypt_directory(self, path):
        self.letsencrypt_directory = self.make_absolute(path)
        self.letsencrypt_live_directory = self.letsencrypt_directory / "live"

    def set_dane_directory(self, path):
        self.dane_directory = self.make_absolute(path)

    def set_ttl(self, ttl):
        self.ttl = ttl

    def set_config_file(self, path):
        self.config = self.make_absolute(path)


class LogType(Enum):
    logfile = 0
    stdout = 1
    none = 3

class LogLevel(Enum):
    nolog = 0
    normal = 1
    verbose = 2
    full = 3

class Log():
    def __init__(self, name, file):
        self.type = LogType.logfile
        self.file = pathlib.Path(file)
        self.level = LogLevel.normal
        self.quiet = False
        self.errors = False

        self.log_out = logging.getLogger("{}:out".format(name))
        self.log_err = logging.getLogger("{}:err".format(name))
        self.log_out.setLevel(logging.INFO)
        self.log_err.setLevel(logging.INFO)

    def __str__(self):
        if self.type == LogType.logfile:
            return "[{}] [q:{}] {}".format(self.level, self.quiet, self.file)
        elif self.ttpe == LogType.stdout:
            return "[{}] [q:{}] {}".format(self.level, self.quiet, self.type)
        else:
            return "{}".format(self.type)

    def set_file(self, file):
        self.type = LogType.logfile
        self.file = pathlib.Path(file)

    def set_stdout(self):
        self.type = LogType.stdout
        self.file = sys.stdout

    def set_nolog(self):
        self.type = LogType.none
        self.file = None

    def set_level(self, level):
        self.level = level

    def set_quiet(self):
        self.quiet = True

    def init(self, progname, progversion, timenow):
        try:
            h2 = logging.StreamHandler(sys.stderr)
            h2.setFormatter( logging.Formatter('%(message)s') )
            self.log_err.addHandler(h2)
        except OSError:
            self.errors = True
            return False

        if self.type == LogType.logfile:
            if self.file.is_dir():
                self.file = self.file / "{}.log".format(progname)

            try:
                self.file = self.file.resolve()
            except FileNotFoundError as ex:
                pass
                # we'll catch the parent directory not existing next. We don't
                # want to exit here if the log file itself doesn't exist.
            except RuntimeError as ex:
                self.error(
                    "log file '{}': file could not be resolved".format(
                                                                ex.filename))
                return False

            if not self.file.parent.exists():
                self.error(
                    "logging: directory '{}' not found".format(
                                                        self.file.parent))
                return False

            # info   -> logfile
            # errors -> logfile
            #        -> stderr
            try:
                h1 = logging.FileHandler(str(self.file))
                h1.setFormatter( logging.Formatter('%(message)s') )
                self.log_out.addHandler(h1)
            except OSError as ex:
                self.error("log file '{}': {}".format(
                                            ex.filename, ex.strerror.lower() ))
                return False

            arg_str = sys.argv[0]
            for a in sys.argv[1:]:
                if ' ' in a or '\t' in a or '\n' in a:
                    arg_str += " '{}'".format(a)
                else:
                    arg_str += " {}".format(a)

            self.info1("---------------------------------------------\n{0} {1}\n{2} ({2:%s})\nprogram run as: {3}\n---------------------------------------------".format(progname, progversion, timenow, arg_str))
        elif self.type == LogType.stdout:
            # info   -> stdout
            # errors -> stderr
            try:
                h1 = logging.StreamHandler(sys.stdout)
                h1.setFormatter( logging.Formatter('%(message)s') )
                self.log_out.addHandler(h1)
            except OSError as ex:
                self.error( "stdout stream failed: {}".format(
                                                        ex.strerror.lower()))
                return False

        return True


    def printmsg(self, msg, level):
        try:
            if self.type == LogType.logfile:
                # printing to log file, ignore 'quiet'
                if level.value <= self.level.value:
                    self.log_out.info(msg)
            elif self.type == LogType.stdout:
                if not self.quiet:
                    if level.value <= self.level.value:
                        self.log_out.info(msg)
        except OSError as ex:
            if not self.errors:
                self.errors = True
                self.warning("logging output failed: {}. Logfile may be incomplete".format(ex.strerror.lower()))

    def info1(self, msg):
        self.printmsg(msg, LogLevel.normal)

    def info2(self, msg):
        self.printmsg(msg, LogLevel.verbose)

    def info3(self, msg):
        self.printmsg(msg, LogLevel.full)

    def error(self, msg):
        lines = msg.splitlines()
        for l in lines:
            try:
                self.log_err.info("error: {}".format(l))
            except OSError:
                self.errors = True

    def warning(self, msg):
        lines = msg.splitlines()
        for l in lines:
            try:
                self.log_err.info("warning: {}".format(l))
            except OSError:
                self.errors = True




class RetVal(Enum):
    ok = 0
    exit_ok = 256
    exit_failure = 1
    continue_failure = 257
    config_failure = 78



class Api:
    def __init__(self, type):
        self.type = type

    def __eq__(self, a):
        return self.type == a.type

class ApiCloudlare4(Api):
    def __init__(self):
        super().__init__(ApiType.cloudflare4)
        self.zone = None
        self.email = None
        self.key = None

    def __str__(self):
        return "    - {}\n       zone: ...({})\n       email: ...({})\n       key: ...({})".format(self.type, len(self.zone), len(self.email), len(self.key))

    def __eq__(self, a):
        return (self.type == a.type and self.zone == a.zone
                and self.email == a.email and self.key == a.key)

class ApiBinary(Api):
    def __init__(self, command, uid=None, gid=None):
        super().__init__(ApiType.binary)
        self.command = command # should be a list object
        self.uid = uid
        self.gid = gid # NOTE: remove?

    def __str__(self):
        return "    - {}\n       command: {} [uid: {}]".format(self.type, self.command, self.uid, self.gid)

    def rstr(self):
        return "[{}]".format("] [".join(self.command)) + " (uid:{})".format(self.uid, self.gid)

    def __eq__(self, a):
        return (self.type == a.type and self.command == a.command
                and self.uid == a.uid and self.gid == a.gid)


class ApiType(Enum):
    cloudflare4 = 0
    binary = 1



class Tlsa:
    def __init__(self, param, port, protocol, domain):
        self.usage = param[0]
        self.selector = param[1]
        self.matching = param[2]
        self.port = port
        self.protocol = protocol
        self.domain = domain
        self.publish = True
            #determines whether this TLSA object should be published
            # and a posthook line created. Normally this is always True. This
            # is only ever False when we have re-renewed a certificate whose
            # hash to publish has not changed. In this case we do not need to
            # publish a TLSA and add a posthook line since this has all
            # already been done

    def __eq__(self, t):
        return ( self.usage == t.usage and self.selector == t.selector
                    and self.matching == t.matching and self.port == t.port
                    and self.protocol == t.protocol
                    and self.domain == t.domain and self.publish == t.publish )

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
    def __init__(self, type, domain, lineno):
        self.type = type
        self.domain = domain
        self.lineno = lineno
        self.state = DataLineState.write

    def write_state_off(self):
        self.state = DataLineState.skip
        #if self.state == DataLineState.write:
        #    self.state = DataLineState.skip
        #else:
        #    self.state = DataLineState.write

class DataPre(DataLine):
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
    pre = 0
    post = 1
    delete = 2

class DataLineState(Enum):
    write = 0
    skip = 1

class DataGroup:
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
    def __init__(self):
        self.groups = [] # List of DataGroup objects

    def add_line(self, prog, line):
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


