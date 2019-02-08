
from alnitak.tests import setup
from alnitak import prog

from pathlib import Path
from subprocess import Popen, PIPE



#    Logging schenarios:
#    1.  flags: <NONE>        info   -> logfile
#                             errors -> logfile, stderr
#    2.  flags: -l-           info   -> stdout
#                             errors -> stderr
#    3.  flags: -lno          info   ->X
#                             errors -> stderr
#    4.  flags: -q            info   -> logfile
#                             errors -> logfile
#    5.  flags: -l- -q        info   ->X
#    6.  flags: -lno -q       errors ->X
#
#    7.  flags: -Lno          info   ->X
#                             errors -> logfile, stderr
#    8.  flags: -l- -Lno      info   ->X
#                             errors -> stderr
#    9.  flags: -lno -Lno     info   ->X
#                             errors -> stderr
#    10. flags: -q -Lno       info   ->X
#                             errors -> logfile
#    11. flags: -l- -q -Lno   info   ->X
#    12. flags: -lno -q -Lno  errors ->X



log_lines_both = [
        'error: config file: no targets given',
        '+++ exiting with code: {}'.format(prog.RetVal.config_failure.value),
        ]

log_lines_error = [ 'error: config file: no targets given' ]


def check_for_both(file):
    with open(str(file), 'r') as f:
        lines = f.read().splitlines()
    assert lines[-2:] == log_lines_both

def check_for_error_only(file):
    with open(str(file), 'r') as f:
        lines = f.read().splitlines()
    assert lines[-1:] == log_lines_error


def test_logging1():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-l', str(s.varlog / 'log'), '-Lfull',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert log.exists()
    check_for_both(log)

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging2():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-l-', '-Lfull',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) > 0
    assert len(stderr) > 0


def test_logging3():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-lno', '-Lfull',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging4():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-l', str(s.varlog / 'log'), '-Lfull', '-q',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert log.exists()
    check_for_both(log)

    assert len(stdout) == 0
    assert len(stderr) == 0


def test_logging5():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-l-', '-Lfull', '-q',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) == 0


def test_logging6():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-lno', '-Lfull', '-q',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) == 0


def test_logging7():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-l', str(s.varlog / 'log'), '-Lno',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert log.exists()
    check_for_error_only(log)

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging8():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-l-', '-Lno',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging9():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-lno', '-Lno',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging10():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-l', str(s.varlog / 'log'), '-Lno', '-q',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert log.exists()
    check_for_error_only(log)

    assert len(stdout) == 0
    assert len(stderr) == 0


def test_logging11():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-l-', '-Lno', '-q',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) == 0


def test_logging12():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', '-t', '-lno', '-Lno', '-q',
            '-c', str(s.configX1)], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) == 0


