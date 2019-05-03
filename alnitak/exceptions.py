
class ConfigError(Exception):
    """Configuration file syntax errors."""
    def __init__(self, message=None):
        self.message = message

class LockError(Exception):
    """Lock file errors."""
    def __init__(self, message=None):
        self.message = message

class FunctionError(Exception):
    """Generic exception for function throws"""
    def __init__(self, message=None):
        self.message = message

class InternalError(Exception):
    """Internal errors."""
    def __init__(self, message=None):
        self.message = message


class DNSExcept(Exception):
    """Base class for exceptions raised in processing data."""
    def __init__(self, message=None):
        self.message = message

class DNSSkip(DNSExcept):
    """Exceptions raised in processing data that are not errors."""
    pass

class DNSError(DNSExcept):
    """Exceptions raised by errors in processing data."""
    pass


class DNSNotLive(DNSSkip):
    """Raised when DNS records are not yet up (not yet 'live')."""
    pass

class DNSSkipProcessing(DNSSkip):
    """Raised when further processing should be skipped."""
    pass


class DNSProcessingError(DNSError):
    """Raised when processing has encountered an error."""
    pass

class DNSNoReturnError(DNSError):
    """Error that should not cause the program to exit non-zero."""
    pass


class PrivError(Exception):
    """Exception for errors raised when dropping privileges."""
    def __init__(self, message=None):
        self.message = message


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

