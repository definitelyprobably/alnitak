
import os
import sys
import pathlib
from enum import Enum
from collections import OrderedDict


class LogType(Enum):
    """Where to log to, if at all."""
    logfile = 0
    stdout = 1
    no = 2

class LogLevel(Enum):
    """Logging level."""
    nolog = 0
    normal = 1
    verbose = 2
    debug = 3

class LogOutput:
    """Class that does the actual logging of information and/or errors.

    Attributes:
        progname (str): the program name.
        progversion (str): the program version.
        timenow (datetime.datetime): UTC time of when the program was run.
        testing_mode (bool): if in testing mode, do not change permissions
            of any created log file.
        file_name (str): the name of the file to log to
        file (file object): the object returned by open.
        info_to_stdout (bool): if we printing info messages to stdout.
        error_to_stderr (bool): if we are printing error messages to stderr.
        info_to_logfile (bool): if we are printing info messages to the
            logfile.
        error_to_logfile (bool): if we are printing error messages to the
            logfile.
        logfile_failure (list(str)): list of error messages encountered when
            trying to write to the logfile.
        stdout_failure (list(str)): list of error messages encountered when
            trying to write to stdout.
        stderr_failure (list(str)): list of error messages encountered when
            trying to write to stderr.
    """
    def __init__(self, progname, progversion, timenow, testing, filename):
        self.progname = progname
        self.progversion = progversion
        self.timenow = timenow
        self.testing_mode = testing
        self.file_name = filename
        self.file = None

        self.info_to_stdout = False
        self.error_to_stderr = True
        self.info_to_logfile = True
        self.error_to_logfile = True

        self.logfile_failure = []
        self.stdout_failure = []
        self.stderr_failure = []

    def send_error(self, message):
        if isinstance(message, str):
            lines = message.splitlines()
        elif isinstance(message, list):
            lines = message
        else:
            # message might be a Prog class object
            lines = [ str(message) ]

        if self.error_to_logfile:
            self.send_to_logfile([ "error: {}\n".format(l) for l in lines ])
        if self.error_to_stderr:
            self.send_to_stderr(
                    '\n'.join(
                        [ "{}: error: {}.".format(self.progname, l)
                            for l in lines ]) )

    def send_info(self, message):
        if isinstance(message, str):
            lines = message.splitlines()
        elif isinstance(message, list):
            lines = message
        else:
            # message might be a Prog class object
            lines = [ str(message) ]

        if self.info_to_logfile:
            self.send_to_logfile([ "{}\n".format(l) for l in lines ])
        if self.info_to_stdout:
            self.send_to_stdout( '\n'.join(lines) )

    def send_to_logfile(self, lines):
        try:
            self.file.writelines(lines)
        except OSError as ex:
            self.logfile_failure += [
                    "{}: '{}'".format(ex.strerror.lower(), ex.filename) ]

    def send_to_stdout(self, message):
        try:
            print(message)
        except OSError as ex:
            self.stdout_failure += [
                    "{}: '{}'".format(ex.strerror.lower(), ex.filename) ]

    def send_to_stderr(self, message):
        try:
            print(message, file=sys.stderr)
        except OSError as ex:
            self.stderr_failure += [
                    "{}: '{}'".format(ex.strerror.lower(), ex.filename) ]

    def set_no_info(self):
        self.info_to_stdout = False
        self.info_to_logfile = False

    def set_info_stdout(self):
        self.info_to_stdout = True
        self.info_to_logfile = False

    def set_info_logfile(self):
        self.info_to_stdout = False
        self.info_to_logfile = True

    def set_no_error(self):
        self.error_to_stderr = False
        self.error_to_logfile = False

    def set_error_stderr(self):
        self.error_to_stderr = True
        self.error_to_logfile = False

    def set_error_logfile(self):
        self.error_to_stderr = False
        self.error_to_logfile = True

    def set_error_all(self):
        self.error_to_stderr = True
        self.error_to_logfile = True

    def open_logfile(self):
        if not (self.info_to_logfile or self.error_to_logfile):
            return

        fpath = pathlib.Path(self.file_name)

        try:
            if fpath.exists():
                if fpath.is_dir():
                    fpath = fpath / "{}.log".format(self.progname)
                    self.file_name = str(fpath)
                    if fpath.exists() and not fpath.is_file():
                        self.logfile_failure += [
                                "logfile '{}' is not a regular file".format(
                                    self.file_name) ]
                        self.info_to_logfile = True
                        self.error_to_logfile = True
                        return
                elif not fpath.is_file():
                    self.logfile_failure += [
                            "logfile '{}' is not a regular file".format(
                                self.file_name) ]
                    self.info_to_logfile = True
                    self.error_to_logfile = True
                    return
            else:
                if not fpath.parent.exists():
                    fpath.parent.mkdir(parents=True)
        except OSError as ex:
            self.logfile_failure += [
                    "logfile '{}' could not be opened: {}: '{}'".format(
                        self.file_name, ex.strerror.lower(), ex.filename) ]
            self.info_to_logfile = True
            self.error_to_logfile = True
            return

        # change permissions of file if it doesn't exist:
        self.change_permissions()

        try:
            self.file = open(self.file_name, 'a')
        except OSError as ex:
            self.logfile_failure += [
                    "logfile '{}' could not be opened: {}".format(
                                            ex.filename, ex.strerror.lower()) ]
            self.info_to_logfile = False
            self.error_to_logfile = False

    def close_logfile(self):
        if not (self.info_to_logfile or self.error_to_logfile):
            return
        self.file.close()

    def change_permissions(self):
        if self.testing_mode:
            return

        fpath = pathlib.Path(self.file_name)

        try:
            with open(self.file_name, 'x'):
                pass
        except FileExistsError:
            return

        try:
            os.chown(self.file_name, 0, 0)
        except OSError as ex:
            self.logfile_failure += [
                    "logfile '{}': changing owner failed: {}".format(
                            self.file_name, ex.strerror.lower()) ]
            # do not set self.*_to_logfile = False: we should still
            # print to the logfile.

        try:
            fpath.chmod(0o600)
        except OSError as ex:
            self.logfile_failure += [
                    "logfile '{}': changing permissions failed: {}".format(
                            self.file_name, ex.strerror.lower()) ]
            # do not set self.*_to_logfile = False: we should still
            # print to the logfile.

    def has_errors(self):
        return (self.logfile_failure or self.stdout_failure
                or self.stderr_failure)

    def finish(self):
        if not self.has_errors():
            return

        output_errs = list(OrderedDict.fromkeys(self.logfile_failure
                                                  + self.stdout_failure
                                                  + self.stderr_failure))

        output_errs += [ "diagnostic output may be incomplete" ]

        self.send_error(output_errs)

    def write_header(self):
        arg_str = sys.argv[0]

        for a in sys.argv[1:]:
            if ' ' in a or '\t' in a or '\n' in a:
                arg_str += " '{}'".format(a)
            else:
                arg_str += " {}".format(a)

        self.send_info([ "---------------------------------------------",
                         "{0} {1}".format(self.progname, self.progversion),
                         "{0} ({0:%s})".format(self.timenow),
                         "program run as: {0}".format(arg_str),
                         "---------------------------------------------" ])

class Log:
    """Class to control logging of information.

    Logging schenarios:
    1.  flags: <NONE>        info   -> logfile
                             errors -> logfile, stderr
    2.  flags: -l-           info   -> stdout
                             errors -> stderr
    3.  flags: -lno          info   ->X
                             errors -> stderr
    4.  flags: -q            info   -> logfile
                             errors -> logfile
    5.  flags: -l- -q        info   ->X
    6.  flags: -lno -q       errors ->X

    7.  flags: -Lno          info   ->X
                             errors -> logfile, stderr
    8.  flags: -l- -Lno      info   ->X
                             errors -> stderr
    9.  flags: -lno -Lno     info   ->X
                             errors -> stderr
    10. flags: -q -Lno       info   ->X
                             errors -> logfile
    11. flags: -l- -q -Lno   info   ->X
    12. flags: -lno -q -Lno  errors ->X

    Attributes:
        type (LogType): the input to the '-l' flag -- the loggin output target.
        level (LogLevel): the input to the '-L' flag -- the logging level.
        quiet (bool): whether the '-q' flag was given or not.
        output (LogOutput): the class object that does the logging itself.
    """
    def __init__(self, name, version, time, testing, file):
        self.type = LogType.logfile # -l
        self.level = LogLevel.normal # -L
        self.quiet = False # -q
        self.output = LogOutput(name, version, time, testing, file)

    def __enter__(self):
        self.set_info_target()
        self.set_error_target()
        self.output.open_logfile()
        self.output.write_header()
        return self

    def __exit__(self, *args):
        self.output.finish()
        self.output.close_logfile()

    def set_info_target(self):
        if (self.level == LogLevel.nolog
                or self.type == LogType.no):
            self.output.set_no_info()
        elif self.type == LogType.stdout:
            if self.quiet:
                self.output.set_no_info()
            else:
                self.output.set_info_stdout()
        else:
            self.output.set_info_logfile()

    def set_error_target(self):
        if self.type == LogType.no or self.type == LogType.stdout:
            if self.quiet:
                self.output.set_no_error()
            else:
                self.output.set_error_stderr()
        else:
            if self.quiet:
                self.output.set_error_logfile()
            else:
                self.output.set_error_all()

    def printmsg(self, msg, level):
        if level.value <= self.level.value:
            self.output.send_info(msg)

    def info1(self, msg):
        self.printmsg(msg, LogLevel.normal)

    def info2(self, msg):
        self.printmsg(msg, LogLevel.verbose)

    def info3(self, msg):
        self.printmsg(msg, LogLevel.debug)

    def error(self, msg):
        self.output.send_error(msg)

    def warning(self, msg):
        self.output.send_info(msg)

    def has_errors(self):
        return self.output.has_errors()

    def set_stdout(self):
        self.type = LogType.stdout

    def set_nolog(self):
        self.type = LogType.no

    def set_file(self, file):
        self.output.file_name = file

    def set_no_logging(self):
        self.level = LogLevel.nolog

    def set_verbose_logging(self):
        self.level = LogLevel.verbose

    def set_debug_logging(self):
        self.level = LogLevel.debug

    def set_quiet(self):
        self.quiet = True

