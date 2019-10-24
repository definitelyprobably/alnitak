
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

    # prog_state = state.State()
    # prog_state.handler = state.PrintHandler()
    # prev_state = None
    #
    # prog_state.call = 'prepare'
    # mode.prepare(prog_state, prev_state)
    #
    # prog_state.call = 'deploy'
    # mode.deploy(prog_state)
    #
    # prog_state.debug_print()



if __name__ == "__main__":
    main()

