
import sys
import re
from enum import Enum

from alnitak import prog as Prog
from alnitak import exceptions as Except
from alnitak import config
from alnitak import datafile
from alnitak import printrecord
from alnitak import dane
from alnitak import logging



def print_check(prog, pos, flag_name, input):
    """Parse inputs to the 'print' mode.

    Args:
        prog (State): program state.
        pos (int): flag command-line position.
        flag_name (str): flag name.
        input (str): input string from the command-line parser.

    Returns:
        Record: object containing the tlsa parameters and certificate/domain
            extracted from the input.

    Raises:
        Error: if the input does not conform. Derived classes thrown are:
            Error1200, Error1210, Error1211, Error1212.
    """
    if len(input) < 5:
        raise Error1200(pos, flag_name, input)

    if input[3] != ':':
        raise Error1200(pos, flag_name, input)

    if input[0] not in ['2', '3']:
        raise Error1210(pos, flag_name, input, input[0])

    if input[1] not in ['0', '1']:
        raise Error1211(pos, flag_name, input, input[1])

    if input[2] not in ['0', '1', '2']:
        raise Error1212(pos, flag_name, input, input[2])

    return Prog.Record(input[:3], input[4:])


def ttl_check(prog, pos, flag_name, input):
    """Parse inputs to the '--ttl' flag.

    Args:
        prog (State): program state.
        pos (int): flag command-line position.
        flag_name (str): flag name.
        input (str): input string from the command-line parser.

    Returns:
        int: returns the input converted to an integer, unmodified.

    Raises:
        Error: if the input does not conform. Derived classes thrown are:
            Error1013, Error1100 or Error1101.
    """
    try:
        ttl = int(input)
    except ValueError:
        raise Error1013(pos, flag_name, input)

    if ttl > prog.ttl_max:
        raise Error1100(pos, flag_name, input, prog.ttl_max)

    if ttl < prog.ttl_min:
        raise Error1101(pos, flag_name, input, prog.ttl_min)

    return ttl



def version_message(prog):
    '''Program version message.

    Args:
        prog (State): program state.

    Returns:
        str: the message to print.
    '''
    return "{} {}\n{}".format(prog.name, prog.version, prog.copyright)

def help_message(prog, mode=None):
    '''Program help message.

    Args:
        prog (State): program state.
        mode (str): the program mode to print the help message for.

    Returns:
        str: the message to print.
    '''
    head='''Automatically manage DANE records when Let's Encrypt certificates are renewed.

Usage: alnitak [mode] [options]

Mode:'''

    modes='''
    <default>       (no explicit mode given) run in default mode.
    pre             run in pre-hook mode.
    deploy          run in deploy-hook mode.
    reset           reset (or create) the dane directory.
    configtest      check the configuration file for errors.
    print           print TLSA certificate data.
'''

    opts_common='''
Options:
    -h, --help          print a help message and exit.
    -V, --version       print the program version number and exit.
'''

    f_flag='''
        --force         force removal of the datafile, if it exists.
'''
    l_flag='''
    -l, --log LOG       write to log file 'LOG'.
'''
    L_flag='''
    -L, --log-level LEVEL
                        set the level of information to log to 'LEVEL', which
                        may be one of:
                            no        do not log anything.
                            normal    default level of logging.
                            verbose   more verbose logging.
                            debug     even more verbose logging.
'''
    c_flag='''
    -c, --config CONF   read configuration file 'CONF' instead of the
                        system default '/etc/alnitak.conf'.
'''
    C_flag='''
    -C, --letsencrypt-directory DIR
                        set the directory containing the Let's Encrypt live
                        and archive directories. By default it is set to
                        '/etc/letsencrypt'.
'''
    D_flag='''
    -D, --dane-directory DIR
                        set the directory where the dane symlinks to the
                        Let's Encrypt certificates are stored. By default
                        this is set to '/etc/alnitak/dane'.
'''
    t_flag='''
    -t, --ttl TIME      set the time, in seconds, before which no revertion
                        of the dane certificate to point to the new
                        Let's Encrypt certificate must be made. Effectively,
                        this is the minimum time set for the TLSA DNS records
                        to propogate before the new certificate is used.
'''
    q_flag='''
    -q, --quiet         do not print errors to the screen. Note that they
                        will still be logged in the log file (unless also
                        told not to), and command line errors will not be
                        affected.
'''

    default='''
    In default mode:
       alnitak [-l LOG] [-L LEVEL] [-C DIR] [-D DIR] [-c CONF] [-t TIME] [-q]

            run in default mode, to process any dane certificates that need
            to be cleaned up after renewal has occurred. 
'''

    prem='''
    pre
       alnitak pre [-l LOG] [-L LEVEL] [-C DIR] [-D DIR] [-c CONF]
                   [-t TIME] [-q]

            run in pre-hook mode, to be run before Let's Encrypt certificate
            renewal, preferably on certbot's '--pre-hook'.
'''
    deploym='''
    deploy
       alnitak deploy [-l LOG] [-L LEVEL] [-C DIR] [-D DIR] [-c CONF]
                      [-t TIME] [-q]

            run in deploy-hook mode, to be run after Let's Encrypt certificate
            renewal, prefably on certbot's '--deploy-hook'.
'''

    resetm='''
    reset
       alnitak reset [-l LOG] [-L LEVEL] [-C DIR] [-D DIR] [-c CONF]
                     [-t TIME] [-q] [--force]

            reset (or recreate) the dane directory.
'''

    configtestm='''
    configtest
       alnitak configtest [-l LOG] [-L LEVEL] [-c CONF] [-q]

            test the configuration file for errors.
'''

    printm='''
    print
       alnitak print [-l LOG] [-L LEVEL] [-C DIR] [-c CONF] [XZY:CERT...]

            print TLSA certificate data for the targets in the configuration
            file if no inputs are given. If inputs 'XYZ:CERT' are given, then
            instead print certificate data for 'CERT' corresponding to TLSA
            usage field 'X', selector field 'Y' and matching type 'Z'.
            'CERT' may either be:
                - path/to/cert.pem
                    print certificate data for the file specified.
                - example.com
                    print certificate data for cert(s) in the Let's Encrypt
                    live directory.
                - live/example.com
                    print certificate data for cert(s) in the Let's Encrypt
                    live directory (/etc/letsencrypt/live/example.com/).
                - archive/example.com
                    print certificate data for cert(s) in the Let's Encrypt
                    archive directory (/etc/letsencrypt/archive/example.com/).
                - archive/example.com/cert1.pem
                    print certificate data for the specific file in the
                    Let's Encrypt directory (/etc/letsencrypt/)
'''
    if not mode.names:
        return "{}{}{}{}{}{}{}{}{}{}{}\n{}".format(
                head, modes, default, opts_common,
                c_flag, C_flag, D_flag, l_flag, L_flag, t_flag, q_flag,
                version_message(prog))
    if 'pre' in mode.names:
        return "{}{}{}{}{}{}{}{}{}{}\n{}".format(
                head, prem, opts_common,
                c_flag, C_flag, D_flag, l_flag, L_flag, t_flag, q_flag,
                version_message(prog))
    if 'deploy' in mode.names:
        return "{}{}{}{}{}{}{}{}{}{}\n{}".format(
                head, deploym, opts_common,
                c_flag, C_flag, D_flag, l_flag, L_flag, t_flag, q_flag,
                version_message(prog))
    if 'reset' in mode.names:
        return "{}{}{}{}{}{}{}{}{}{}{}\n{}".format(
                head, resetm, opts_common,
                c_flag, C_flag, D_flag, f_flag, l_flag, L_flag, t_flag, q_flag,
                version_message(prog))
    if 'configtest' in mode.names:
        return "{}{}{}{}{}{}{}\n{}".format(
                head, configtestm, opts_common,
                c_flag, l_flag, L_flag, q_flag,
                version_message(prog))
    if 'print' in mode.names:
        return "{}{}{}{}{}{}{}\n{}".format(
                head, printm, opts_common,
                c_flag, C_flag, l_flag, L_flag,
                version_message(prog))

    return "{}{}{}{}{}{}{}{}{}{}{}\n{}".format(
            head, modes, default, opts_common,
            c_flag, C_flag, D_flag, l_flag, L_flag, t_flag, q_flag,
            version_message(prog))



class Error(Exception):
    '''Base class for command-line parsing errors.'''
    def __init__(self, errno, pos, arg, ref):
        self.errno = errno
        self.pos = pos
        self.arg = arg
        self.ref = ref

class Error1000(Error):
    '''Mode not recognized.'''
    def __init__(self, arg):
        super().__init__(1000, None, arg, None)
    def __str__(self):
        return "mode '{}' not recognized".format(self.arg)

class Error1010(Error):
    '''Input to mandatory flag missing.'''
    def __init__(self, pos, arg):
        super().__init__(1010, pos, arg, None)
    def __str__(self):
        return "arg {}: flag '{}': required input missing".format(
                self.pos, self.arg)

class Error1011(Error):
    '''Bare flag given an input.'''
    def __init__(self, pos, arg, ref):
        super().__init__(1011, pos, arg, ref)
    def __str__(self):
        return "arg {}: flag '{}': does not take an input: '{}'".format(
                self.pos, self.arg, self.ref)

class Error1012(Error):
    '''Bare long flag given an empty input.'''
    def __init__(self, pos, arg):
        super().__init__(1012, pos, arg, None)
    def __str__(self):
        return "arg {}: flag '{}': does not expect an input".format(
                self.pos, self.arg)

class Error1013(Error):
    '''Input to flag not recognized.'''
    def __init__(self, pos, arg, ref):
        super().__init__(1013, pos, arg, ref)
    def __str__(self):
        return "arg {}: flag '{}': input not recognized: '{}'".format(
                self.pos, self.arg, self.ref)

class Error1020(Error):
    '''Unrecognized flag.'''
    def __init__(self, pos, arg):
        super().__init__(1020, pos, arg, None)
    def __str__(self):
        return "arg {}: flag '{}': unrecognized flag".format(
                self.pos, self.arg)

class Error1021(Error):
    '''Unrecognized input.'''
    def __init__(self, pos, arg):
        super().__init__(1021, pos, arg, None)
    def __str__(self):
        return "arg {}: input '{}': unrecognized input".format(
                self.pos, self.arg)

class Error1100(Error):
    '''Error for ttl flag: input exceeds maximum value.'''
    def __init__(self, pos, arg, ref, max):
        super().__init__(1100, pos, arg, ref)
        self.max = max
    def __str__(self):
        return "arg {}: flag '{}': input '{}' exceeds maximum value of '{}'".format(self.pos, self.arg, self.ref, self.max)

class Error1101(Error):
    '''Error for ttl flag: input below minimum value.'''
    def __init__(self, pos, arg, ref, min):
        super().__init__(1101, pos, arg, ref)
        self.min = min
    def __str__(self):
        return "arg {}: flag '{}': input '{}' below minimum value of '{}'".format(self.pos, self.arg, self.ref, self.min)

class Error1200(Error):
    '''Error for print mode: malformed input.'''
    def __init__(self, pos, arg, ref):
        super().__init__(1200, pos, arg, ref)
    def __str__(self):
        return "arg {}: flag '{}': malformed input '{}': must be like 'XYZ:CERT'".format(self.pos, self.arg, self.ref)

class Error1210(Error):
    '''Error for print mode: malformed usage value.'''
    def __init__(self, pos, arg, ref, spec):
        super().__init__(1210, pos, arg, ref)
        self.spec = spec
    def __str__(self):
        return "arg {}: flag '{}': input '{}': usage value '{}' not recognized".format(self.pos, self.arg, self.ref, self.spec)

class Error1211(Error):
    '''Error for print mode: malformed selector value.'''
    def __init__(self, pos, arg, ref, spec):
        super().__init__(1211, pos, arg, ref)
        self.spec = spec
    def __str__(self):
        return "arg {}: flag '{}': input '{}': selector value '{}' not recognized".format(self.pos, self.arg, self.ref, self.spec)

class Error1212(Error):
    '''Error for print mode: malformed matching type value.'''
    def __init__(self, pos, arg, ref, spec):
        super().__init__(1212, pos, arg, ref)
        self.spec = spec
    def __str__(self):
        return "arg {}: flag '{}': input '{}': matching type value '{}' not recognized".format(self.pos, self.arg, self.ref, self.spec)





class FlagType(Enum):
    '''Argument type.'''
    bare = 0
    option = 1
    mandatory = 2


class Flag:
    '''Class encoding a flag object.

    This class represents the definition of a flag object.

    Attributes:
        type (FlagType): the flag type.
        short_names (list): the list of 'short' names (e.g., '-a', '-b').
        long_names (list): the list of 'long' names (e.g., '--foo', '--bar').
        input (str): the input to the flag, if present (and appropriate).
        input_match (str|function): either a regex string to match the input
            against, or else a function that should do the matching. Either
            way, if the input to the flag does not pass this check, the
            input to the flag is regarded as invalid.
    '''
    def __init__(self, type, *args, **kwargs):
        self.type = type
        self.short_names = []
        self.long_names = []
        self.input = None
        self.input_match = None
        for arg in args:
            if arg.startswith('--'):
                self.long_names += [ arg ]
            elif arg.startswith('-'):
                self.short_names += [ arg ]
            else:
                self.long_names += [ arg ]

        for key, value in kwargs.items():
            if key == 'match':
                self.input_match = value

    def canonical(self):
        '''The 'canonical' name used by the Parser.has function.'''
        if self.short_names:
            return self.short_names[0][1]
        elif self.long_names[0].startswith('--'):
            return self.long_names[0][2:]
        return self.long_names[0]

    def __str__(self):
        return "{} {} {}".format(self.type, self.short_names, self.long_names)


class Mode:
    '''Class encoding the group of flags constituting a command-line mode.

    When the program is called like:
        $ alnitak pre -a -b -c ...
    then the mode is 'pre' and the flags '-a', '-b', '-c'... belong to the
    group of flags that are only valid for that mode.

    Attributes:
        names (*str): the name(s) of the mode, or else 'None' for the
            default mode, which is that mode when no explicit mode name is
            given on the command line.
        flags (list(Flag)): the list of flags valid for this mode group.
        collect (str|function|True): in addition to the flags valid for
            this mode, the parser can also collect any arguments given.
            Those arguments that are valid inputs to the command can be
            either tested against a regex, tested against a function to call,
            or else unconditionally accepted with a value of 'True'.
    '''
    def __init__(self, *names):
        if names:
            self.names = [ *names ]
        else:
            self.names = None
        self.flags = []
        self.collect = None

    def add_bare(self, *args):
        self.flags += [ Flag(FlagType.bare, *args) ]
        return self

    def add_option(self, *args, **kwargs):
        self.flags += [ Flag(FlagType.option, *args, **kwargs) ]
        return self

    def add_mandatory(self, *args, **kwargs):
        self.flags += [ Flag(FlagType.mandatory, *args, **kwargs) ]
        return self

    def add_flag(self, *args):
        for a in args:
            self.flags += [ a ]
        return self

    def set_collect_if(self, expr):
        self.collect = expr


class Instance:
    '''Class recording instances of flags given at the command line.

    Attributes:
        flag (Flag): the Flag instance that matched.
        pos (int): the postion on the command line the instance was on.
        subpos (int): the position in the argument for sconcatenated flags.
            For example, for '-abc', instance '-a' would have subpos 'None',
            instance '-b' would have subpos 2 and instance '-c' would have
            subpos 3.
        flag_complete (str): the complete command-line argument. For example,
            for '--flag=input', flag_complete would have value '--flag=input',
            but note that for '--flag input', flag_complete would have value
            '--flag'.
        flag_name (str): the flag name. For '--flag=input' and '--flag input',
            this would be set to '--flag'. For '-finput' it would be '-f'.
            For '-fginput' where '-f' and '-g' are flags, the '-g' flag would
            have this set to '-g' and not 'g'.
        flag_input (str): the input to the flag. For '--flag=input' and
            '--flag input', this would be set to 'input'. For bare flags
            and option flags with no input, this will be set to 'None'.
    '''
    def __init__(self, flag, pos, flag_complete, flag_name, flag_input=None,
                 subpos=None):
        self.flag = flag
        self.pos = pos
        self.subpos = subpos
        self.flag_complete = flag_complete
        self.flag_name = flag_name
        self.flag_input = flag_input

    def __str__(self):
        if self.subpos:
            return "  o {} @{}.{} ::  {} {}".format(
                self.flag_complete, self.pos, self.subpos, self.flag_name,
                self.flag_input)
        else:
            return "  o {} @{} ::  {} {}".format(
                self.flag_complete, self.pos, self.flag_name, self.flag_input)

    def instance(self):
        return Instance(self.flag, self.pos, self.flag_complete,
                        self.flag_name, self.flag_input, self.subpos)


class Spit:
    '''Class to retrieve the next flag, including from concatenated flags.

    Attributes:
        cl_args (list(str)): the command line arguments.
        pos (int): the index position in cl_args of the last argument that
            the 'next' function returned.
    '''
    def __init__(self, args):
        self.cl_args = args
        self.pos = 0

    def next(self, subpos=None):
        if subpos:
            return '-' + self.cl_args[self.pos][subpos:]
        else:
            self.pos += 1
            try:
                return self.cl_args[self.pos]
            except IndexError:
                return None

    def reset(self):
        self.pos = 0


class Parser:
    '''Class to parse the command-line arguments.

    Attributes:
        prog (State): program state.
        cl (Spit): the command-line arguments to parse, set in 'parse_args'.
        modes (dict): the modes defined to the parser, stored as a dict:
            'name': Mode('name')
        common_flags (list(Flag)): list of flags common to all modes.
        active_mode (Mode): the mode that is in effect. If the default mode
            is in effect, then it is set to 'None'.
        active_flags (list(Flag)): all the flags in effect, a combination of
            the flags in 'common_flags' and the flags in the active mode.
        instances (list(Instance)): list of flag instances detected on the
            command line.
        errors (list(Error)): list of errors detected.
        inputs (list): list of command-line inputs (arguments that are not
            flags or flag inputs). The type in the list will be either a
            str object, or else a type returned by a matching function.
        has_flag (dict(str: list(Instance))): a dict for the list of
            instances present for a flag. The key is the canonical name
            for the flag, and the value is the list of instances of that
            flag.
    '''
    def __init__(self, prog):
        self.prog = prog
        self.cl = None
        self.modes = {}
        self.common_flags = []

        self.active_mode = None
        self.active_flags = []

        self.instances = []
        self.errors = []
        self.inputs = []

        self.has_flag = {}

    def add_mode(self, mode):
        if mode.names:
            self.modes[mode.names[0]] = mode
        else:
            self.modes[mode.names] = mode

    def add_bare(self, *args):
        self.common_flags += [ Flag(FlagType.bare, *args) ]
        return self

    def add_option(self, *args, **kwargs):
        self.common_flags += [ Flag(FlagType.option, *args, **kwargs) ]
        return self

    def add_mandatory(self, *args, **kwargs):
        self.common_flags += [ Flag(FlagType.mandatory, *args, **kwargs) ]
        return self

    def add_flag(self, *args):
        for a in args:
            self.common_flags += [ a ]
        return self

    def has(self, flag):
        try:
            instance = self.has_flag[flag][-1]
            if instance.flag_input:
                return instance.flag_input
            return True
        except (KeyError, IndexError):
            return False

    def is_mode(self, mode):
        if self.active_mode.names:
            return mode in self.active_mode.names
        else:
            return mode == self.active_mode.names

    def split_long(self, flag):
        m = re.match(r'(?P<name>[^=]+)(=(?P<input>.*))?$', flag)
        return (m.group('name'), m.group('input'))

    def parse_args(self, args=None):
        if args:
            self.cl = Spit(args)
        else:
            import sys
            self.cl = Spit(sys.argv)

        # reset values
        self.active_mode = None
        self.active_flags = []

        self.instances = []
        self.errors = []
        self.inputs = []

        self.has_flag = {}


        # get the mode
        mode_name = self.cl.next()
        if not mode_name:
            return False

        if mode_name.startswith('-'):
            self.cl.reset()
            mode_name = None

        # at this point, the mode_name has been set (including set to None
        # if in default mode).

        if mode_name:
            for mode in self.modes.values():
                # Note: one of the modes might be the default one and have
                # mode.names = None, so need to skip that one
                if mode.names and mode_name in mode.names:
                    self.active_mode = mode
                    self.active_flags = mode.flags + self.common_flags
                    collect = mode.collect
                    break
            else:
                self.errors += [ Error1000(mode_name) ]
                # cannot process flags that follow since we don't know
                # what to expect, so exit
                return True
        else:
            # if default mode defined, load it; otherwise just set the common
            # settings. Note: do this even if no default mode was added.
            try:
                self.active_mode = self.modes[mode_name]
                self.active_flags = self.common_flags + self.active_mode.flags
                collect = self.active_mode.collect
            except KeyError:
                self.active_flags = self.common_flags
                collect = None


        defer = None
        subpos = None

        while True:
            arg = self.cl.next(subpos)
            if not arg:
                break

            is_long = False
            if arg.startswith('--') or not arg.startswith('-'):
                is_long = True
                name, input = self.split_long(arg)
            else:
                name = arg[:2]
                input = arg[2:]

            for ref_flag in self.active_flags:
                if is_long:
                    if name in ref_flag.long_names:
                        defer = self.process_long_name(arg, name, input,
                                                       defer, ref_flag)
                        break
                else:
                    if name in ref_flag.short_names:
                        defer, subpos = self.process_short_name(
                                                arg, name, input, defer,
                                                ref_flag, subpos)
                        break
            else:
                # input not a recognized flag/argument.
                subpos = None
                defer, collect = self.process_unrecognized(arg, name, input,
                                                           defer, collect)

        # defer still set after all the command-line args have been processed
        if defer:
            if defer.flag.type == FlagType.option:
                self.instances += [ defer.instance() ]
            else:
                self.errors += [ Error1010(defer.pos, defer.flag_name) ]


        present_flags = { i.flag.canonical() for i in self.instances }
        self.has_flag = {
                p: [ i for i in self.instances if i.flag.canonical() == p ]
                for p in present_flags
                }

        if self.errors:
            return True
        return False

    def process_long_name(self, arg, name, input, defer, ref_flag):
        if defer:
            if defer.flag.type == FlagType.option:
                self.instances += [ defer.instance() ]
            else:
                self.errors += [ Error1010(defer.pos, defer.flag_name) ]
            defer = None

        if ref_flag.type == FlagType.bare:
            if input:
                self.errors += [ Error1011(self.cl.pos, name, input) ]
            elif input != None:
                self.errors += [ Error1012(self.cl.pos, name) ]
            else:
                self.instances += [
                        Instance(ref_flag, self.cl.pos, arg, name) ]
        else:
            if input:
                if ref_flag.input_match:
                    if isinstance(ref_flag.input_match, str):
                        m = re.match(ref_flag.input_match, input)
                        if m:
                            self.instances += [ Instance(ref_flag, self.cl.pos,
                                                         arg, name, input) ]
                        else:
                            self.errors += [
                                        Error1013(self.cl.pos, name, input) ]
                    else:
                        try:
                            res = ref_flag.input_match(self.prog, self.cl.pos,
                                                       name, input)
                            self.instances += [ Instance(ref_flag, self.cl.pos,
                                                         arg, name, res) ]
                        except Error as ex:
                            self.errors += [ ex ]
                else:
                    self.instances += [
                            Instance(ref_flag, self.cl.pos, arg, name, input) ]
            elif input != None:
                self.errors += [ Error1010(self.cl.pos, name) ]
            else:
                defer = Instance(ref_flag, self.cl.pos, arg, name)

        return defer

    def process_short_name(self, arg, name, input, defer, ref_flag, subpos):
        if defer:
            if defer.flag.type == FlagType.mandatory:
                # catches -bm -b (bare: -b, man: -m)
                self.errors += [ Error1010(defer.pos, defer.flag_name) ]
            else:
                self.instances += [ defer.instance() ]
            defer = None

        if ref_flag.type == FlagType.bare:
            if input:
                defer = Instance(ref_flag, self.cl.pos, arg, name, None,
                                 subpos)
                if subpos:
                    subpos += 1
                else:
                    subpos = 2
            else:
                self.instances += [ Instance(ref_flag, self.cl.pos, arg,
                                             name, None, subpos) ]
                subpos = None
        else:
            if input:
                if ref_flag.input_match:
                    if isinstance(ref_flag.input_match, str):
                        m = re.match(ref_flag.input_match, input)
                        if m:
                            self.instances += [ Instance(ref_flag, self.cl.pos,
                                                         arg, name, input,
                                                         subpos) ]
                        else:
                            self.errors += [
                                        Error1013(self.cl.pos, name, input) ]
                    else:
                        try:
                            res = ref_flag.input_match(self.prog, self.cl.pos,
                                                       name, input)
                            self.instances += [ Instance(ref_flag, self.cl.pos,
                                                         arg, name, res) ]
                        except Error as ex:
                            self.errors += [ ex ]
                else:
                    self.instances += [ Instance(ref_flag, self.cl.pos, arg,
                                                 name, input, subpos) ]
            else:
                defer = Instance(ref_flag, self.cl.pos, arg, name, None,
                                 subpos)
            subpos = None

        return (defer, subpos)

    def process_unrecognized(self, arg, name, input, defer, collect):
        if defer:
            if defer.flag.type == FlagType.bare:
                # prev was a bare (short) flag, this is not a flag, so
                # we need to print an error:
                self.errors += [
                            Error1011(defer.pos, defer.flag_name, name[1:]) ]
            else:
                if defer.flag.input_match:
                    if isinstance(defer.flag.input_match, str):
                        m = re.match(defer.flag.input_match, arg)
                        if m:
                            defer.flag_input = arg
                            self.instances += [ defer.instance() ]
                        else:
                            self.errors += [
                                    Error1013(defer.pos, defer.flag_name, arg) ]
                    else:
                        try:
                            res = defer.flag.input_match(self.prog, defer.pos,
                                                         defer.flag_name, arg)
                            defer.flag_input = res
                            self.instances += [ defer.instance() ]
                        except Error as ex:
                            self.errors += [ ex ]
                else:
                    defer.flag_input = arg
                    self.instances += [ defer.instance() ]
            defer = None

        elif collect:
            if collect == True:
                self.inputs += [ arg ]
            elif isinstance(collect, str):
                m = re.match(collect, arg)
                if m:
                    self.inputs += [ arg ]
                elif arg.startswith('-'):
                    self.errors += [ Error1020(self.cl.pos, name) ]
                else:
                    self.errors += [ Error1021(self.cl.pos, name) ]
            else:
                try:
                    res = collect(self.prog, self.cl.pos, name, arg)
                    self.inputs += [ res ]
                except Error as ex:
                    if arg.startswith('-'):
                        self.errors += [ Error1020(self.cl.pos, name) ]
                    else:
                        self.errors += [ ex ]

        else:
            if arg.startswith('-'):
                self.errors += [ Error1020(self.cl.pos, name) ]
            else:
                self.errors += [ Error1021(self.cl.pos, name) ]

        return (defer, collect)


def parse_args(prog):
    """Parse the command line.

    Parse the command line, set the program state and return a list of
    functions to be called for the program's operation, determined from the
    command line arguments.

    Args:
        prog (State): program's state.

    Returns:
        list: returns a list of functions that should be called,
            corresponding to the mode to be run.
    """

    C_flag = Flag(FlagType.mandatory, '-C', '--letsencrypt-directory')
    D_flag = Flag(FlagType.mandatory, '-D', '--dane-directory')
    t_flag = Flag(FlagType.mandatory, '-t', '--ttl', match=ttl_check)
    q_flag = Flag(FlagType.bare, '-q', '--quiet')


    p = Parser(prog)

    p.add_bare('-h', '--help')
    p.add_bare('-V', '--version')
    p.add_mandatory('-c', '--config')
    p.add_mandatory('-l', '--log')
    p.add_mandatory('-L', '--log-level', match=r'(no|normal|verbose|debug)$')

    defm = Mode()
    defm.add_flag(C_flag, D_flag, t_flag, q_flag)
    p.add_mode(defm)

    prem = Mode('pre', 'prehook')
    prem.add_flag(C_flag, D_flag, t_flag, q_flag)
    p.add_mode(prem)

    deploym = Mode('deploy', 'deployhook', 'post', 'posthook')
    deploym.add_flag(C_flag, D_flag, t_flag, q_flag)
    p.add_mode(deploym)

    resetm = Mode('reset', 'init')
    resetm.add_flag(C_flag, D_flag, t_flag, q_flag)
    resetm.add_bare('--force')
    p.add_mode(resetm)

    configm = Mode('configtest')
    configm.add_flag(q_flag)
    p.add_mode(configm)

    printm = Mode('print')
    printm.add_flag(C_flag)
    printm.set_collect_if(print_check)
    p.add_mode(printm)

    if p.parse_args():
        for err in p.errors:
            print("{}: error: {}.".format(prog.name, err), file=sys.stderr)
        sys.exit(2)


    if p.has('h'):
        print(help_message(prog, p.active_mode))
        sys.exit(0)

    if p.has('V'):
        print(version_message(prog))
        sys.exit(0)

    ttl = p.has('t')
    if ttl:
        prog.set_ttl(ttl)

    # must set 'prog.log.quiet' before the other 'prog.log' details.
    if p.has('q'):
        prog.log.set_quiet()

    log = p.has('l')
    if log:
        if log in [ 'stdout', '-' ]:
            prog.log.set_stdout()
        elif log == 'no':
            prog.log.set_nolog()
        else:
            if log[-1] == '/':
                prog.log.set_file("{}/{}.log".format(log, prog.name))
            else:
                prog.log.set_file(log)

    loglevel = p.has('L')
    if loglevel:
        if loglevel == 'verbose':
            prog.log.set_verbose_logging()
        elif loglevel == 'debug':
            prog.log.set_debug_logging()
        elif loglevel == 'no':
            prog.log.set_no_logging()

    dd = p.has('D')
    if dd:
        prog.set_dane_directory(dd)

    le = p.has('C')
    if le:
        prog.set_letsencrypt_directory(le)

    conf = p.has('c')
    if conf:
        prog.set_config_file(conf)


    if p.is_mode('print'):
        # do not log anything below 'debug':
        if prog.log.level in [logging.LogLevel.normal,
                              logging.LogLevel.verbose]:
            prog.log.set_no_logging()

        # FIXME: need to remove duplicates in args.printrecord, not just
        #        identical entries but also 311:a.com and 311:live/a.com

        if p.inputs:
            exec_list = [ printrecord.populate_targets,
                          printrecord.certificate_data ]
        else:
            exec_list = [ config.read, printrecord.certificate_data ]

    elif p.is_mode('configtest'):
        exec_list = [ config.read ]

    elif p.is_mode('reset'):
        prog.recreate_dane = True
        exec_list = [ config.read, datafile.remove, dane.init_dane_directory ]

    elif p.is_mode('prehook'):
        exec_list = [ config.read, dane.init_dane_directory,
                      dane.live_to_archive, datafile.write_prehook ]

    elif p.is_mode('deployhook'):
        exec_list = [ config.read, dane.set_renewed_domains, datafile.read,
                      datafile.check_data, dane.process_data,
                      datafile.write_posthook ]

    else:
        exec_list = [ config.read, dane.set_renewed_domains, datafile.read,
                      datafile.check_data, dane.process_data,
                      datafile.write_posthook ]

    # save the args
    prog.args = p

    return exec_list

