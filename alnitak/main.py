
from pprint import pprint # XXX
import os # XXX
import pathlib # XXX
import re # XXX
from alnitak import fsops # XXX

from alnitak import state
from alnitak import mode



def main():
    # frontend operations
    #
    # 1. read command line
    # 2. read config file, set the state object
    # 3. get renewed domains
    # 4. read/write statefile, by importing/exporting state object
    # 5. locking
    #
    # TODO: what happens if, when reading the statefile, some data is fiddled
    #       with? E.g., if enum values have been changed? We could put a
    #       CRC hash in, but what happens if we detect a tampering? Continue
    #       as far as possible? Bug out straight away? Probably the latter
    #       is safer.
    # TODO: statefile: should try hard to write one; maybe waiting and trying
    #       again if it didn't work?



    # backend operations
    #
    #
    # organized by mode:
    #   - prepare
    #   - deploy
    #   - print
    #   - init
    #   - reset
    #   - state
    #   - test
    #
    # e.g., run prepare operations with arguments to the prepare function:
    #
    # call: mode.prepare(force=False, state=state)
    #
    #
    #
    #
    #

    print("entry: main")

    base_dir = pathlib.Path.cwd() / 'z_root'
    def_dane = pathlib.Path(base_dir) / 'etc/al'
    def_le =   pathlib.Path(base_dir) / 'etc/le'
    api_bin =  pathlib.Path(base_dir) / 'usr/bin/certs'

    prog_state = state.State()
    prev_state = state.State()


    # PREPARE MODE
    #
    # frontend: read command line -> populate 'Prog' object
    # frontend: read config file(s) -> populate 'prog_state'
    # (frontend: lock program)
    # (frontend: initiate logging)
    # frontend: read statefile if it is present -> populate 'prev_prog_state'.
    # call prepare(...)

    #prog_state.handler = TESTING_handler()
    prog_state.handler = state.PrintHandler()

    prog_state.create_target('a.com')
    prog_state.create_target('b.com')

    prog_state.set_dane_directory('a.com', pathlib.Path(def_dane))
    prog_state.set_letsencrypt_directory('a.com', pathlib.Path(def_le))

    prog_state.set_dane_directory('b.com', pathlib.Path(def_dane))
    prog_state.set_letsencrypt_directory('b.com', pathlib.Path(def_le))

    prog_state.create_api_exec('a.com', [ api_bin ])
    prog_state.create_api_exec('b.com', [ api_bin ])


    prev_state.create_target('X.com')
    prev_state.set_progress_deployed('X.com')

    prev_state.create_record('X.com', 3, 1, 1, 25, 'tcp', 'XXX.X.com')
    prev_state.set_prev_record('X.com', '311', 'abcdef0123456789')

    prog_state.create_record('a.com', 3, 1, 1, 25, 'tcp')

    ### unset ###
    prev_state = None


    # RUN INIT FIRST
    #prog_state.call = 'init'
    #mode.prepare(prog_state, prev_state)

    #TESTING_display(prog_state, [ 'a.com', 'b.com' ], 'BEFORE PREPARE:')

    prog_state.call = 'prepare'
    mode.prepare(prog_state, prev_state)

    #TESTING_display(prog_state, [ 'a.com', 'b.com' ], 'AFTER PREPARE:')

    #print(prog_state.handler.errors)

    TESTING_simulate_renew(prog_state, ['a.com'])

    prog_state.call = 'deploy'
    mode.deploy(prog_state)
    print("renewed: {}".format(prog_state.renewed_domains))

    #TESTING_display(prog_state, [ 'a.com', 'b.com' ], 'AFTER DEPLOY:')


    #print("---- STATE ------------------------------")
    #pprint(prog_state.targets)
    prog_state.debug_print()


def TESTING_display(prog_state, domains = [], message = None):

    if message:
        print("{}".format(message))

    for d in prog_state.targets:

        if d not in domains:
            continue
        print("--- {} -------------------".format(d))

        target = prog_state.targets[d]

        lddir = (target['letsencrypt_directory'] / 'live') / d

        print("live: {}".format(lddir))

        live_links = [ l.name for l in lddir.iterdir()
                            if l.is_symlink() and l.is_file() ]

        for l in live_links:
            print("  live: {} -> {}".format(l, os.readlink( str(lddir / l) ) ))


        ddir = (target['dane_directory'] / d)

        print("dane: {}".format(ddir))

        dane_links = [ l.name for l in ddir.iterdir()
                            if l.is_symlink() and l.is_file() ]

        for l in dane_links:
            print("  dane: {} -> {}".format(l, os.readlink( str(ddir / l) ) ))

    if message:
        print("")




class TESTING_handler:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def warning(self, message):
        self.warnings += [ message ]

    def error(self, message):
        self.errors += [ message ]


def TESTING_simulate_renew(pstate, domains = None):


    for d in pstate.targets:
        if d not in domains:
            continue

        target = pstate.targets[d]

        prev_no = None
        new_no = None

        for c in [ 'cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem' ]:
            cert = target['live_domain_directory'] / c

            arx = cert.resolve()

            m = re.match(r'([a-z]+)([0-9])\.pem', arx.name)

            if m.group(2) == '1':
                prev_no = 1
                new_no = 2
                new_arx = ( target['archive_domain_directory'] /
                                        "{}2.pem".format(m.group(1)) )
            if m.group(2) == '2':
                prev_no = 2
                new_no = 3
                new_arx = ( target['archive_domain_directory'] /
                                        "{}3.pem".format(m.group(1)) )
            if m.group(2) == '3':
                prev_no = 3
                new_no = 1
                new_arx = ( target['archive_domain_directory'] /
                                        "{}1.pem".format(m.group(1)) )

            cert.unlink()

            cert.symlink_to( fsops.relative_to(cert, new_arx) )


        print("TESTING> renewed '{}': {} -> {}".format(d, prev_no, new_no))
        

if __name__ == "__main__":
    main()


