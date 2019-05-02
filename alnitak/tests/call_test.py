
import os

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


def test_logging0():
    # if running as root, the other tests will run as intended, so we can
    # skip this test...
    if os.getuid() == 0:
        return

    # ...otherwise, the other tests will artificially create log files if
    # they don't already exist because changing the permissions of the log
    # file will fail if not root; let's test that failure here

    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', 'configtest', '-l', str(s.varlog / 'log'),
                                        '-c', str(s.config)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.ok.value + 16

    assert log.exists()
    assert log.stat().st_size > 0

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging1():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    # if not run as root, log creation will fail; so we need to artificially
    # create the log file first
    if os.getuid() != 0:
        with open(str(s.varlog / 'log'), 'w'):
            pass

    p = Popen(['alnitak', 'configtest', '-l', str(s.varlog / 'log'),
                                        '-Ldebug',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

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

    p = Popen(['alnitak', 'configtest', '-l-',
                                        '-Ldebug',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) > 0
    assert len(stderr) > 0


def test_logging3():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', 'configtest', '-lno',
                                        '-Ldebug',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging4():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    # if not run as root, log creation will fail; so we need to artificially
    # create the log file first
    if os.getuid() != 0:
        with open(str(s.varlog / 'log'), 'w'):
            pass

    p = Popen(['alnitak', 'configtest', '-l', str(s.varlog / 'log'),
                                        '-Ldebug',
                                        '-q',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

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

    p = Popen(['alnitak', 'configtest', '-l-',
                                        '-Ldebug',
                                        '-q',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) == 0


def test_logging6():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', 'configtest', '-lno',
                                        '-Ldebug',
                                        '-q',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) == 0


def test_logging7():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    # if not run as root, log creation will fail; so we need to artificially
    # create the log file first
    if os.getuid() != 0:
        with open(str(s.varlog / 'log'), 'w'):
            pass

    p = Popen(['alnitak', 'configtest', '-l', str(s.varlog / 'log'),
                                        '-Lno',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

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

    p = Popen(['alnitak', 'configtest', '-l-',
                                        '-Lno',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging9():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', 'configtest', '-lno',
                                        '-Lno',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) > 0


def test_logging10():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    # if not run as root, log creation will fail; so we need to artificially
    # create the log file first
    if os.getuid() != 0:
        with open(str(s.varlog / 'log'), 'w'):
            pass

    p = Popen(['alnitak', 'configtest', '-l', str(s.varlog / 'log'),
                                        '-Lno',
                                        '-q',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

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

    p = Popen(['alnitak', 'configtest', '-l-',
                                        '-Lno',
                                        '-q',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) == 0


def test_logging12():
    s = setup.Init(keep=True)
    log = Path(s.varlog / 'log')

    assert not log.exists()

    p = Popen(['alnitak', 'configtest', '-lno',
                                        '-Lno',
                                        '-q',
                                        '-c', str(s.configX1)],
              stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)

    assert p.returncode == prog.RetVal.config_failure.value

    assert not log.exists()

    assert len(stdout) == 0
    assert len(stderr) == 0


