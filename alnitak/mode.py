
from alnitak import fsops


def prepare(state, prev_state = None):
    '''
    '''

    fsops.init_dane_directory(state)

    fsops.cleanup_prev_state(state, prev_state)

    fsops.process_deletes(state)


def deploy(state):
    '''
    '''

    fsops.process_deletes(state)

    fsops.set_renewed(state)

    fsops.process_deployed(state)


def printt():
    '''
    '''

def init():
    '''
    '''

def test():
    '''
    '''

def state():
    '''
    '''

