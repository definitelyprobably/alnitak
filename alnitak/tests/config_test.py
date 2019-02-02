
from pathlib import Path

from alnitak import prog as Prog
from alnitak import config
from alnitak.tests import setup


def test_config_default():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))

    t_a1 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    t_a2 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1, t_a2])

    t_b1 = setup.create_tlsa_obj('311', '12780', 'udp', 'b.com')
    t_b2 = setup.create_tlsa_obj('201', '12780', 'sctp', 'A.b.com')
    tb = setup.create_target_obj('b.com', api, [], [t_b1, t_b2])

    t_c1 = setup.create_tlsa_obj('311', '12722', 'tcp', 'A.c.com')
    t_c2 = setup.create_tlsa_obj('311', '12723', 'tcp', 'B.c.com')
    tc = setup.create_target_obj('c.com', api, [], [t_c1, t_c2])

    assert prog.target_list == [ta, tb, tc]
    assert prog.dane_directory == cwd / s.dane
    assert prog.letsencrypt_directory == cwd / s.le


def test_config1():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.config1)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))

    t_a200 = setup.create_tlsa_obj('200', '12725', 'tcp', 'a.com')
    t_a201 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    t_a202 = setup.create_tlsa_obj('202', '12725', 'tcp', 'a.com')
    t_a210 = setup.create_tlsa_obj('210', '12725', 'tcp', 'a.com')
    t_a211 = setup.create_tlsa_obj('211', '12725', 'tcp', 'a.com')
    t_a212 = setup.create_tlsa_obj('212', '12725', 'tcp', 'a.com')
    t_a300 = setup.create_tlsa_obj('300', '12725', 'tcp', 'a.com')
    t_a301 = setup.create_tlsa_obj('301', '12725', 'tcp', 'a.com')
    t_a302 = setup.create_tlsa_obj('302', '12725', 'tcp', 'a.com')
    t_a310 = setup.create_tlsa_obj('310', '12725', 'tcp', 'a.com')
    t_a311 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    t_a312 = setup.create_tlsa_obj('312', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [],
            [t_a200, t_a201, t_a202, t_a210, t_a211, t_a212,
             t_a300, t_a301, t_a302, t_a310, t_a311, t_a312])

    assert prog.target_list == [ta]
    assert prog.dane_directory == cwd / s.dane
    assert prog.letsencrypt_directory == cwd / s.le


def test_config2():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.config2)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    t_a2 = setup.create_tlsa_obj('211', '12725', 'tcp', 'a.com')
    t_a3 = setup.create_tlsa_obj('301', '12725', 'tcp', 'a.com')
    t_a4 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1, t_a2, t_a3, t_a4])

    assert prog.target_list == [ta]
    assert prog.dane_directory == cwd / s.dane
    assert prog.letsencrypt_directory == cwd / s.le


def test_config6():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.config6)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api0 = setup.create_api_binary_obj(str(s.bin / 'dns'))
    api1 = setup.create_api_binary_obj('bin', '--flag1', 'input',
                                       "input with\t whitespace")
    api2 = setup.create_api_c4_obj(zone='ZONE', email='me@domain.com',
                                   key='KEY')

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    t_a2 = setup.create_tlsa_obj('211', '12725', 'tcp', 'a.com')
    t_a3 = setup.create_tlsa_obj('301', '12725', 'tcp', 'a.com')
    t_a4 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api1, [], [t_a1, t_a2, t_a3, t_a4])

    t_b1 = setup.create_tlsa_obj('200', '1', 'sctp', 'b.com')
    t_b2 = setup.create_tlsa_obj('201', '1', 'sctp', 'W.com')
    t_b3 = setup.create_tlsa_obj('202', '1', 'tcp', 'X.com')
    t_b4 = setup.create_tlsa_obj('210', '1', 'sctp', 'Y.com')
    t_b5 = setup.create_tlsa_obj('211', '1', 'sctp', 'Z.com')
    t_b6 = setup.create_tlsa_obj('212', '1', 'sctp', 'A.com')
    t_b7 = setup.create_tlsa_obj('212', '1', 'udp', 'B.com')
    tb = setup.create_target_obj('b.com', api2, [],
                                 [t_b1, t_b2, t_b3, t_b4, t_b5, t_b6, t_b7])

    t_c1 = setup.create_tlsa_obj('200', '2', 'tcp', 'c.com')
    tc = setup.create_target_obj('c.com', api0, [], [t_c1])

    assert prog.target_list == [ta, tb, tc]
    assert prog.dane_directory == Path('/tmp/Q')
    assert prog.letsencrypt_directory == cwd / '../relative_path'



def test_fail_configX1():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX1)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    assert prog.target_list == []
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX2():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX2)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX3():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX3)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    assert prog.target_list == []
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX4():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX4)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    assert prog.target_list == []
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX5():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX5)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    assert prog.target_list == []
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX6():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX6)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX7():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX7)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX8():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX8)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX9():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX9)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX10():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX10)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX11():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX11)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX12():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX12)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX13():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX13)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX14():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX14)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX15():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX15)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    t_a1 = setup.create_tlsa_obj('202', '1', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX16():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX16)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    t_a1 = setup.create_tlsa_obj('202', '1', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', None, [], [t_a1])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX17():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX17)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    t_a1 = setup.create_tlsa_obj('202', '1', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1])

    assert prog.target_list == [ta]
    assert prog.dane_directory == cwd / s.dane
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX18():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX18)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    t_a1 = setup.create_tlsa_obj('202', '1', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == cwd / s.le


def test_fail_configX19():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX19)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    api = setup.create_api_binary_obj(str(s.bin / 'dns'))
    ta = setup.create_target_obj('a.com', api, [], [])

    assert prog.target_list == [ta]
    assert prog.dane_directory == Path('/tmp')
    assert prog.letsencrypt_directory == Path('/var/tmp')


def test_fail_configX20():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX20)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    t_a1 = setup.create_tlsa_obj('202', '1', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', None, [], [t_a1])

    assert prog.target_list == [ta]
    assert prog.dane_directory == cwd / s.dane
    assert prog.letsencrypt_directory == cwd / s.le


def test_fail_configX21():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX21)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    t_a1 = setup.create_tlsa_obj('202', '1', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', None, [], [t_a1])

    assert prog.target_list == [ta]
    assert prog.dane_directory == cwd / s.dane
    assert prog.letsencrypt_directory == cwd / s.le


def test_fail_configX22():
    s = setup.Init(keep=True)
    prog = setup.create_state_obj(s, config=s.configX22)
    cwd = Path.cwd()

    assert prog.log.init(prog.name, prog.version, prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.config_failure

    t_a1 = setup.create_tlsa_obj('202', '1', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', None, [], [t_a1])

    assert prog.target_list == [ta]
    assert prog.dane_directory == cwd / s.dane
    assert prog.letsencrypt_directory == cwd / s.le


