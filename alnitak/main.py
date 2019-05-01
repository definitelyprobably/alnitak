
import sys
from alnitak import prog as Prog
from alnitak import parser


def exit(prog, value=0, tolog=True):
    """Exit depending on the internal program state."""
    # so far, the only error setting that might be set is prog.log.errors.
    if prog.log.has_errors():
        value += 16
    if tolog:
        prog.log.info3("+++ exiting with code: {}".format(value))
    sys.exit(value)

def create_lock(prog):
    try:
        if prog.lock():
            if not prog.args.has('q'):
                try:
                    print("{}: another instance is already running.".format(
                          prog.name))
                except OSError:
                    prog.log.output.stdout_failure = True
            exit(prog, 32, False)
    except Except.LockError as ex:
        if not prog.args.has('q'):
            try:
                print("{}: error: {}.".format(prog.name, ex.message),
                      file=sys.stderr)
            except OSError:
                prog.log.output.stderr_failure = True
        exit(prog, 4, False)

def main():
    """Alnitak program entry function."""

    # create program state object
    prog = Prog.State()

    # parse command line arguments
    exec_list = parser.parse_args(prog)

    # first create a lock:
    create_lock(prog)

    # next initialize logging
    with prog.log:

        # then run the program code (given in 'exec_list')
        errors = False
        for prog_call in exec_list:
            retval = prog_call(prog)
            if retval == Prog.RetVal.ok:
                continue
            elif retval == Prog.RetVal.exit_ok:
                exit(prog)
            elif retval == Prog.RetVal.continue_failure:
                errors = True
            else:
                exit(prog, retval.value)

        if errors:
            exit(prog, 1)
        exit(prog)

if __name__ == "__main__":
    main()

