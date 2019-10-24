
from alnitak import fsops


def prepare(state, prev_state = None):
    '''
    '''

    # The truly backend functions are:
    # dane.init_dane_directory,
    # dane.live_to_archive [NOT NEEDED],

    fsops.init_dane_directory(state)

    fsops.cleanup_prev_state(state, prev_state)

    fsops.process_deletes(state)


def deploy(state):
    '''
    '''

    # dane.set_renewed_domains,
    # dane.process_data,

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

