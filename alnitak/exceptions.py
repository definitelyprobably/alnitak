
class ConfigError(RuntimeError):
    """Configuration file syntax errors."""
    def __init__(self, message=None):
        self.message = message

class LockError(RuntimeError):
    """Lock file errors."""
    def __init__(self, message=None):
        self.message = message

class FunctionError(RuntimeError):
    """Generic exception for function throws"""
    def __init__(self, message=None):
        self.message = message

class InternalError(RuntimeError):
    """Internal errors."""
    def __init__(self, message=None):
        self.message = message


class DNSExcept(RuntimeError):
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


class PrivError(RuntimeError):
    """Exception for errors raised when dropping privileges."""
    def __init__(self, message=None):
        self.message = message
