
class ConfigError(RuntimeError):
    def __init__(self, message=None):
        self.message = message

class InternalError(RuntimeError):
    def __init__(self, message=None):
        self.message = message


class DNSExcept(RuntimeError):
    def __init__(self, message=None):
        self.message = message

class DNSSkip(DNSExcept):
    pass

class DNSError(DNSExcept):
    pass


class DNSNotLive(DNSSkip):
    pass

class DNSSkipProcessing(DNSSkip):
    pass


class DNSProcessingError(DNSError):
    pass

class DNSNoReturnError(DNSError):
    pass


class PrivError(RuntimeError):
    def __init__(self, message=None):
        self.message = message
