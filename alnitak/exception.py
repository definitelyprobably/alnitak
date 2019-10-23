
class AlnitakException(Exception):
    """Alnitak exceptions"""
    def __init__(self, message=None):
        self.message = message

class AlnitakError(AlnitakException):
    """Alnitak runtime error"""
    pass

class AlnitakInternalError(AlnitakException):
    """Alnitak internal error"""
    pass

class AlnitakResolveError(Exception):
    """Alnitak resolving error"""
    def __init__(self, filename, strerror):
        self.filename = filename
        self.strerror = strerror


