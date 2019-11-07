
class AlnitakException(Exception):
    '''Alnitak exceptions'''
    def __init__(self, message=None):
        self.message = message

class AlnitakError(AlnitakException):
    '''Alnitak runtime error'''
    pass

class AlnitakResolveError(AlnitakException):
    '''Alnitak resolving error'''
    def __init__(self, filename, strerror):
        self.filename = filename
        self.strerror = strerror

