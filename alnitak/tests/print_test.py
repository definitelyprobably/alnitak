
from alnitak.tests import setup
from alnitak import prog
from subprocess import Popen, PIPE
from pathlib import Path

def tos(state, domain, params, name, num = None):
    p = Path.cwd()
    if num:
        hn = num
        p = p / state.domains[domain]['archive'] / (name + str(num) + ".pem")
    else:
        hn = 1
        p = p / state.domains[domain]['live'] / (name + ".pem")

    sparams = str(params)
    data = state.hash[domain]['cert' + str(hn)][int(params)]

    return "{} {} {} {} {}".format(p, sparams[0], sparams[1], sparams[2], data)


def test_print1():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    # [a.com]
    # tlsa = 311 12725
    # tlsa = 201 12725
    assert ( tos(s, 'a.com', 311, 'cert') in cdata or
             tos(s, 'a.com', 311, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 201, 'chain') in cdata or
             tos(s, 'a.com', 201, 'fullchain') in cdata )

    # [b.com]
    # tlsa = 311 12780 udp
    # tlsa = 201 12780 sctp A.b.com
    assert ( tos(s, 'b.com', 311, 'cert') in cdata or
             tos(s, 'b.com', 311, 'fullchain') in cdata )
    assert ( tos(s, 'b.com', 201, 'chain') in cdata or
             tos(s, 'b.com', 201, 'fullchain') in cdata )

    # [c.com]
    # tlsa = 311 12722 A.c.com
    # tlsa = 311 12723 B.c.com
    assert ( tos(s, 'c.com', 311, 'cert') in cdata or
             tos(s, 'c.com', 311, 'fullchain') in cdata )

    assert len(cdata) == 5



def test_print2():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config1), '-C', str(s.le),
               '-p'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    # [a.com]
    # tlsa = 200 12725
    # tlsa = 201 12725
    # tlsa = 202 12725
    # tlsa = 210 12725
    # tlsa = 211 12725
    # tlsa = 212 12725
    # tlsa = 300 12725
    # tlsa = 301 12725
    # tlsa = 302 12725
    # tlsa = 310 12725
    # tlsa = 311 12725
    # tlsa = 312 12725
    assert ( tos(s, 'a.com', 200, 'chain') in cdata or
             tos(s, 'a.com', 200, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 201, 'chain') in cdata or
             tos(s, 'a.com', 201, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 202, 'chain') in cdata or
             tos(s, 'a.com', 202, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 210, 'chain') in cdata or
             tos(s, 'a.com', 210, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 211, 'chain') in cdata or
             tos(s, 'a.com', 211, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 212, 'chain') in cdata or
             tos(s, 'a.com', 212, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 300, 'cert') in cdata or
             tos(s, 'a.com', 300, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 301, 'cert') in cdata or
             tos(s, 'a.com', 301, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 302, 'cert') in cdata or
             tos(s, 'a.com', 302, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 310, 'cert') in cdata or
             tos(s, 'a.com', 310, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 311, 'cert') in cdata or
             tos(s, 'a.com', 311, 'fullchain') in cdata )
    assert ( tos(s, 'a.com', 312, 'cert') in cdata or
             tos(s, 'a.com', 312, 'fullchain') in cdata )

    assert len(cdata) == 12



def test_print3():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p', '200:b.com'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'b.com', 200, 'chain') in cdata or
             tos(s, 'b.com', 200, 'fullchain') in cdata )

    assert len(cdata) == 1



def test_print4():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p', '201:b.com', '-p'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'b.com', 201, 'chain') in cdata or
             tos(s, 'b.com', 201, 'fullchain') in cdata )

    assert len(cdata) == 1



def test_print5():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p', '-p', '202:b.com'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'b.com', 202, 'chain') in cdata or
             tos(s, 'b.com', 202, 'fullchain') in cdata )

    assert len(cdata) == 1



def test_print6():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p210:b.com'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'b.com', 210, 'chain') in cdata or
             tos(s, 'b.com', 210, 'fullchain') in cdata )

    assert len(cdata) == 1



def test_print7():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p211:b.com', '-p'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'b.com', 211, 'chain') in cdata or
             tos(s, 'b.com', 211, 'fullchain') in cdata )

    assert len(cdata) == 1



def test_print8():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p', '-p212:b.com'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'b.com', 212, 'chain') in cdata or
             tos(s, 'b.com', 212, 'fullchain') in cdata )

    assert len(cdata) == 1



def test_print9():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
        '-p300:b.com', '-p', '301:b.com'], stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'b.com', 300, 'cert') in cdata or
             tos(s, 'b.com', 300, 'fullchain') in cdata )
    assert ( tos(s, 'b.com', 301, 'cert') in cdata or
             tos(s, 'b.com', 301, 'fullchain') in cdata )

    assert len(cdata) == 2



def test_print10():
    s = setup.Init(keep=True)

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p302:b.com', '-p', '310:b.com', '311:b.com',
               '-p', '312:b.com'],
               stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'b.com', 302, 'cert') in cdata or
             tos(s, 'b.com', 302, 'fullchain') in cdata )
    assert ( tos(s, 'b.com', 310, 'cert') in cdata or
             tos(s, 'b.com', 310, 'fullchain') in cdata )
    assert ( tos(s, 'b.com', 311, 'cert') in cdata or
             tos(s, 'b.com', 311, 'fullchain') in cdata )
    assert ( tos(s, 'b.com', 312, 'cert') in cdata or
             tos(s, 'b.com', 312, 'fullchain') in cdata )

    assert len(cdata) == 4



def test_print11():
    s = setup.Init(keep=True)

    cwd = Path.cwd()

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p',
               '-p', '200:live/c.com',
               '-p', '201:archive/c.com',
               '-p202:{}/{}/c.com'.format(cwd, s.live),
               '-p', '210:{}/{}/c.com/chain2.pem'.format(cwd, s.archive),
                     '211:{}/{}/c.com'.format(cwd, s.archive),
               '-p', '212:{}/{}/c.com/fullchain.pem'.format(cwd, s.live),
               '-p', '300:live/c.com/fullchain.pem',
               '-p', '301:live/c.com',
               '-p', '302:live/c.com/cert.pem',
               '-p', '310:archive/c.com/fullchain1.pem',
               '-p', '311:archive/c.com',
               '-p', '312:archive/c.com/cert1.pem',
               '-p', '-p'],
               stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    print(cdata)

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'c.com', 200, 'chain') in cdata or
             tos(s, 'c.com', 200, 'fullchain') in cdata )

    assert ( tos(s, 'c.com', 201, 'chain', 1) in cdata or
             tos(s, 'c.com', 201, 'fullchain', 1) in cdata )
    assert ( tos(s, 'c.com', 201, 'chain', 2) in cdata or
             tos(s, 'c.com', 201, 'fullchain', 2) in cdata )
    assert ( tos(s, 'c.com', 201, 'chain', 3) in cdata or
             tos(s, 'c.com', 201, 'fullchain', 3) in cdata )

    assert ( tos(s, 'c.com', 202, 'chain') in cdata or
             tos(s, 'c.com', 202, 'fullchain') in cdata )

    assert   tos(s, 'c.com', 210, 'chain', 2) in cdata

    assert ( tos(s, 'c.com', 211, 'chain', 1) in cdata or
             tos(s, 'c.com', 211, 'fullchain', 1) in cdata )
    assert ( tos(s, 'c.com', 211, 'chain', 2) in cdata or
             tos(s, 'c.com', 211, 'fullchain', 2) in cdata )
    assert ( tos(s, 'c.com', 211, 'chain', 3) in cdata or
             tos(s, 'c.com', 211, 'fullchain', 3) in cdata )

    assert   tos(s, 'c.com', 212, 'fullchain') in cdata

    assert   tos(s, 'c.com', 300, 'fullchain') in cdata

    assert ( tos(s, 'c.com', 301, 'cert') in cdata or
             tos(s, 'c.com', 301, 'fullchain') in cdata )

    assert   tos(s, 'c.com', 302, 'cert') in cdata

    assert   tos(s, 'c.com', 310, 'fullchain', 1) in cdata

    assert ( tos(s, 'c.com', 311, 'cert', 1) in cdata or
             tos(s, 'c.com', 311, 'fullchain', 1) in cdata )
    assert ( tos(s, 'c.com', 311, 'cert', 2) in cdata or
             tos(s, 'c.com', 311, 'fullchain', 2) in cdata )
    assert ( tos(s, 'c.com', 311, 'cert', 3) in cdata or
             tos(s, 'c.com', 311, 'fullchain', 3) in cdata )

    assert   tos(s, 'c.com', 312, 'cert', 1) in cdata

    assert len(cdata) == 18



def test_print12():
    s = setup.Init(keep=True)

    cwd = Path.cwd()

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p',
               '-p', '300:live/a.com',

               '301:archive/a.com',

               '302:live/a.com/cert.pem',
               '310:live/a.com/fullchain.pem',
               '311:archive/a.com/cert2.pem',
               '312:archive/a.com/fullchain3.pem',

               '300:{}/{}/b.com/cert.pem'.format(cwd, s.live),
               '301:{}/{}/b.com/fullchain.pem'.format(cwd, s.live),
               '302:{}/{}/b.com/cert3.pem'.format(cwd, s.archive),
               '310:{}/{}/b.com/fullchain2.pem'.format(cwd, s.archive),

               '-p', '-p'],
               stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    print(cdata)

    assert p.returncode == prog.RetVal.ok.value

    assert len(stdout) > 0
    assert len(stderr) == 0

    assert ( tos(s, 'a.com', 300, 'cert') in cdata or
             tos(s, 'a.com', 300, 'fullchain') in cdata )

    assert ( tos(s, 'a.com', 301, 'cert', 1) in cdata or
             tos(s, 'a.com', 301, 'fullchain', 1) in cdata )
    assert ( tos(s, 'a.com', 301, 'cert', 2) in cdata or
             tos(s, 'a.com', 301, 'fullchain', 2) in cdata )
    assert ( tos(s, 'a.com', 301, 'cert', 3) in cdata or
             tos(s, 'a.com', 301, 'fullchain', 3) in cdata )

    assert   tos(s, 'a.com', 302, 'cert') in cdata
    assert   tos(s, 'a.com', 310, 'fullchain') in cdata
    assert   tos(s, 'a.com', 311, 'cert', 2) in cdata
    assert   tos(s, 'a.com', 312, 'fullchain', 3) in cdata

    assert   tos(s, 'b.com', 300, 'cert') in cdata
    assert   tos(s, 'b.com', 301, 'fullchain') in cdata
    assert   tos(s, 'b.com', 302, 'cert', 3) in cdata
    assert   tos(s, 'b.com', 310, 'fullchain', 2) in cdata

    assert len(cdata) == 12



def test_printX1():
    s = setup.Init(keep=True)

    cwd = Path.cwd()

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p',
               '-p300:{}/{}/a.com/cert.pem'.format(cwd, s.archive),
               '-p', '-p'],
               stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    print(cdata)

    assert p.returncode == prog.RetVal.exit_failure.value

    assert len(stdout) == 0
    assert len(stderr) > 0



def test_printX2():
    s = setup.Init(keep=True)

    cwd = Path.cwd()

    p = Popen(['alnitak', '-lno', '-Lno', '-c', str(s.config), '-C', str(s.le),
               '-p',
               '-p300:{}/{}'.format(cwd, s.archive),
               '-p', '-p'],
               stdout=PIPE, stderr=PIPE)

    stdout, stderr = p.communicate(timeout=300)
    cdata = stdout.decode('ascii').splitlines()

    print(cdata)

    assert p.returncode == prog.RetVal.exit_failure.value

    assert len(stdout) == 0
    assert len(stderr) > 0



