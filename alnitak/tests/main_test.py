
import os
import sys
import pwd
import shlex
from time import sleep
from pathlib import Path
import pytest

from alnitak import main
from alnitak import config
from alnitak import datafile
from alnitak import prog as Prog
from alnitak import certop
from alnitak.tests import setup

sleep_time = 0

def test_success_config_default():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config3)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

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
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'


    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = { 'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
           'b.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
           'c.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
         }

    assert len(prog.dane_domain_directories) == 3
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'privkey1.pem', 0),
                setup.prehook_line(s, cwd, 'c.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'c.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'c.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'c.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)



    # first posthook call (no certificate changes)
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][311] ],
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][201] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    # must have been two calls to the 'dns' binary (two calls to publish the
    # two TLSA records)
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 311, s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "", 201, s.hash['a.com']['cert1'][201]),
            ]
    assert cl == calls



    # posthook (renewed again: no certificate changes)
    sleep(sleep_time)
    setup.clear_state(prog)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][311] ],
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][201] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    # still two calls to the 'dns' binary since cert hashes match
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 311, s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "", 201, s.hash['a.com']['cert1'][201]),
            ]
    assert cl == calls



    # posthook (no renewal, ttl not passed)
    sleep(sleep_time)
    setup.clear_state(prog)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][311] ],
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][201] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    # _still_ two calls to the 'dns' binary since ttl not passed
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 311, s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "", 201, s.hash['a.com']['cert1'][201]),
            ]
    assert cl == calls



    # posthook (proper renewal -- certs changed)
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)

    s.renew_a()
    s.renew_b()

    prog.renewed_domains = [ 'a.com', 'b.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert2'][311] ],
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][201] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    # ordinarily, there would be two more calls per tlsa record since the new
    # certs have a different hash, so we need to delete the old 'new' record
    # that was published, and then publish this new one. However, the 201
    # record still would be the same, so actually only 2 more calls are made
    # instead of 4:
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 311, s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "", 201, s.hash['a.com']['cert1'][201]),
            setup.call_line('p', "", 311, s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "", 311, s.hash['a.com']['cert1'][311]),
            ]
    assert cl == calls




    # posthook (no renewal, ttl passed)
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    # two more calls to the 'dns' binary to delete (or not if the records
    # match -- it's up to the binary to check that)
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 311, s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "", 201, s.hash['a.com']['cert1'][201]),
            setup.call_line('p', "", 311, s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "", 311, s.hash['a.com']['cert1'][311]),
            setup.call_line('d', "", 201, s.hash['a.com']['cert1'][201],
                                          s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "", 311, s.hash['a.com']['cert1'][311],
                                          s.hash['a.com']['cert2'][311]),
            ]
    assert cl == calls


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name


def test_success_2xx_up_config_default():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config3)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

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
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'


    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = { 'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
           'b.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
           'c.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
         }

    assert len(prog.dane_domain_directories) == 3
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'privkey1.pem', 0),
                setup.prehook_line(s, cwd, 'c.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'c.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'c.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'c.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)



    # first posthook call (no certificate changes)
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--is-up=201' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    # must have been two calls to the 'dns' binary (two calls to publish the
    # two TLSA records)
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--is-up=201", 311,
                            s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            ]
    assert cl == calls



    # posthook (renewed again: no certificate changes)
    sleep(sleep_time)
    setup.clear_state(prog)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--is-up=201' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    # still two calls to the 'dns' binary since cert hashes match
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--is-up=201", 311,
                            s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            ]
        # there is another call for the 201 record since, on the first
        # posthook call the 201 record was already up and so not posthook line
        # was written, as opposed for the 311 record. Now, when the certs were
        # renewed again, the 311 record wasn't checked again because we had a
        # posthook line with pending '0' and the cert hashes matched, so we
        # did not need to try to publish again; however, since there is
        # no 201 record posthook line, then the program calls the dns program
        # to try to publish a record again.
    assert cl == calls



    # posthook (no renewal, ttl not passed)
    sleep(sleep_time)
    setup.clear_state(prog)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert1'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    # _still_ two calls to the 'dns' binary since ttl not passed
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--is-up=201", 311,
                            s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            ]
    assert cl == calls



    # posthook (proper renewal -- certs changed)
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)

    s.renew_a()
    s.renew_b()

    prog.renewed_domains = [ 'a.com', 'b.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--is-up=201' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    # ordinarily, there would be two more calls per tlsa record since the new
    # certs have a different hash, so we need to delete the old 'new' record
    # that was published, and then publish this new one. However, the 201
    # record still would be the same, so actually only 2 more calls are made
    # instead of 4:
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--is-up=201", 311,
                            s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            setup.call_line('p', "--is-up=201", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "--is-up=201", 311,
                            s.hash['a.com']['cert1'][311]),
            ]
    assert cl == calls




    # posthook (no renewal, ttl passed)
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    # two more calls to the 'dns' binary to delete (or not if the records
    # match -- it's up to the binary to check that)
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--is-up=201", 311,
                            s.hash['a.com']['cert1'][311]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert1'][201]),
            setup.call_line('p', "--is-up=201", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('p', "--is-up=201", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "--is-up=201", 311,
                            s.hash['a.com']['cert1'][311]),
            setup.call_line('d', "", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl == calls


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name


def test_hashes():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s, config=s.config1)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config4)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

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
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'


    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = {'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ]}

    assert len(prog.dane_domain_directories) == 1
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)



    # first posthook call (publish succeeds)
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    s.renew_a()
    s.renew_b()
    prog.renewed_domains = [ 'a.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    postlines = []
    for n in [200, 201, 202, 210, 211, 212, 300, 301, 302, 310, 311, 312]:
        postlines += [ [ 'a.com', str(n), '12725', 'tcp', 'a.com', ptime, '0',
                         s.hash['a.com']['cert2'][n] ] ]
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
            ]
    lines += postlines
    assert sorted(df_lines) == sorted(lines)

    # must have been twelve calls to the 'dns' binary (to publish)
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 200,
                            s.hash['a.com']['cert2'][200]),
            setup.call_line('p', "", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "", 202,
                            s.hash['a.com']['cert2'][202]),
            setup.call_line('p', "", 210,
                            s.hash['a.com']['cert2'][210]),
            setup.call_line('p', "", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "", 212,
                            s.hash['a.com']['cert2'][212]),
            setup.call_line('p', "", 300,
                            s.hash['a.com']['cert2'][300]),
            setup.call_line('p', "", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "", 302,
                            s.hash['a.com']['cert2'][302]),
            setup.call_line('p', "", 310,
                            s.hash['a.com']['cert2'][310]),
            setup.call_line('p', "", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('p', "", 312,
                            s.hash['a.com']['cert2'][312]),
            ]
    assert cl == calls



    # posthook (renewed again -- certs changed)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)

    s.renew_a()
    s.renew_b()
    prog.renewed_domains = [ 'a.com', 'b.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    postlines = []
    for n in [200, 201, 202, 210, 211, 212]:
        postlines += [ [ 'a.com', str(n), '12725', 'tcp', 'a.com', ptime, '0',
                         s.hash['a.com']['cert3'][n] ] ]
    for n in [300, 301, 302, 310, 311, 312]:
        postlines += [ [ 'a.com', str(n), '12725', 'tcp', 'a.com', ptime2, '0',
                         s.hash['a.com']['cert3'][n] ] ]
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
            ]
    lines += postlines
    assert sorted(df_lines) == sorted(lines)

    # ordinarily, there would be two more calls per tlsa record since the new
    # certs have a different hash, so we need to delete the old 'new' record
    # that was published, and then publish this new one. However, the 2xx
    # records still would be the same, so actually only 12 more calls are made
    # instead of 24:
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 300,
                            s.hash['a.com']['cert3'][300]),
            setup.call_line('p', "", 301,
                            s.hash['a.com']['cert3'][301]),
            setup.call_line('p', "", 302,
                            s.hash['a.com']['cert3'][302]),
            setup.call_line('p', "", 310,
                            s.hash['a.com']['cert3'][310]),
            setup.call_line('p', "", 311,
                            s.hash['a.com']['cert3'][311]),
            setup.call_line('p', "", 312,
                            s.hash['a.com']['cert3'][312]),

            setup.call_line('d', "", 300,
                            s.hash['a.com']['cert2'][300]),
            setup.call_line('d', "", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "", 302,
                            s.hash['a.com']['cert2'][302]),
            setup.call_line('d', "", 310,
                            s.hash['a.com']['cert2'][310]),
            setup.call_line('d', "", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "", 312,
                            s.hash['a.com']['cert2'][312]),
            ]
    assert cl[12:] == calls



    # posthook (no renewal, ttl passed)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    # twelve more calls to the 'dns' binary to delete (or not if the records
    # match -- it's up to the binary to check that)
    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "", 200,
                            s.hash['a.com']['cert1'][200],
                            s.hash['a.com']['cert3'][200]),
            setup.call_line('d', "", 201,
                            s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert3'][201]),
            setup.call_line('d', "", 202,
                            s.hash['a.com']['cert1'][202],
                            s.hash['a.com']['cert3'][202]),
            setup.call_line('d', "", 210,
                            s.hash['a.com']['cert1'][210],
                            s.hash['a.com']['cert3'][210]),
            setup.call_line('d', "", 211,
                            s.hash['a.com']['cert1'][211],
                            s.hash['a.com']['cert3'][211]),
            setup.call_line('d', "", 212,
                            s.hash['a.com']['cert1'][212],
                            s.hash['a.com']['cert3'][212]),

            setup.call_line('d', "", 300,
                            s.hash['a.com']['cert1'][300],
                            s.hash['a.com']['cert3'][300]),
            setup.call_line('d', "", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert3'][301]),
            setup.call_line('d', "", 302,
                            s.hash['a.com']['cert1'][302],
                            s.hash['a.com']['cert3'][302]),
            setup.call_line('d', "", 310,
                            s.hash['a.com']['cert1'][310],
                            s.hash['a.com']['cert3'][310]),
            setup.call_line('d', "", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert3'][311]),
            setup.call_line('d', "", 312,
                            s.hash['a.com']['cert1'][312],
                            s.hash['a.com']['cert3'][312]),
            ]
    assert cl[24:] == calls


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name



def test_2xx_only():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s, config=s.config7)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config8)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1])

    t_b1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'b.com')
    t_b2 = setup.create_tlsa_obj('212', '12725', 'tcp', 'b.com')
    tb = setup.create_target_obj('b.com', api, [], [t_b1, t_b2])

    assert prog.target_list == [ta, tb]
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'

    assert os.readlink(str(s.dane / 'b.com' / 'cert.pem')) == \
                                        '../../le/live/b.com/cert.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'chain.pem')) == \
                                        '../../le/live/b.com/chain.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'fullchain.pem')) == \
                                        '../../le/live/b.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'privkey.pem')) == \
                                        '../../le/live/b.com/privkey.pem'

    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = { 'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
           'b.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
         }

    assert len(prog.dane_domain_directories) == 2
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    assert os.readlink(str(s.dane / 'b.com' / 'cert.pem')) == \
                                        '../../le/archive/b.com/cert1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'chain.pem')) == \
                                        '../../le/archive/b.com/chain1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'fullchain.pem')) == \
                                        '../../le/archive/b.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'privkey.pem')) == \
                                        '../../le/archive/b.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)



    # first posthook call
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    s.renew_a()
    s.renew_b()
    prog.renewed_domains = [ 'a.com', 'b.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [str(s.bin / 'dns')]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                setup.prehook_line(s, cwd, 'b.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'b.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'b.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'b.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'b.com', '201', '12725', 'tcp', 'b.com', ptime, '0',
                  s.hash['b.com']['cert2'][201] ],
                [ 'b.com', '212', '12725', 'tcp', 'b.com', ptime, '0',
                  s.hash['b.com']['cert2'][212] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "", 201,
                            s.hash['b.com']['cert2'][201]),
            setup.call_line('p', "", 212,
                            s.hash['b.com']['cert2'][212]),
            ]
    assert cl == calls


    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    assert os.readlink(str(s.dane / 'b.com' / 'cert.pem')) == \
                                        '../../le/archive/b.com/cert1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'chain.pem')) == \
                                        '../../le/archive/b.com/chain1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'fullchain.pem')) == \
                                        '../../le/archive/b.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'privkey.pem')) == \
                                        '../../le/archive/b.com/privkey1.pem'




    # posthook renewed again
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    s.renew_a()
    s.renew_b()
    prog.renewed_domains = [ 'a.com', 'b.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), '--is-up=201:212' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                setup.prehook_line(s, cwd, 'b.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'b.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'b.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'b.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'b.com', '201', '12725', 'tcp', 'b.com', ptime, '0',
                  s.hash['b.com']['cert2'][201] ],
                [ 'b.com', '212', '12725', 'tcp', 'b.com', ptime, '0',
                  s.hash['b.com']['cert2'][212] ],
            ]
    assert sorted(df_lines) == sorted(lines)


    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "", 201,
                            s.hash['b.com']['cert2'][201]),
            setup.call_line('p', "", 212,
                            s.hash['b.com']['cert2'][212]),
            ]
    assert cl == calls


    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    assert os.readlink(str(s.dane / 'b.com' / 'cert.pem')) == \
                                        '../../le/archive/b.com/cert1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'chain.pem')) == \
                                        '../../le/archive/b.com/chain1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'fullchain.pem')) == \
                                        '../../le/archive/b.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'privkey.pem')) == \
                                        '../../le/archive/b.com/privkey1.pem'



    # ttl passed
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime3 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), "--is-up=201:212" ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--is-up=201:212", 201,
                            s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "--is-up=201:212", 201,
                            s.hash['b.com']['cert1'][201],
                            s.hash['b.com']['cert2'][201]),
            setup.call_line('d', "--is-up=201:212", 212,
                            s.hash['b.com']['cert1'][212],
                            s.hash['b.com']['cert2'][212]),
            ]
    assert cl[3:] == calls


    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'

    assert os.readlink(str(s.dane / 'b.com' / 'cert.pem')) == \
                                        '../../le/live/b.com/cert.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'chain.pem')) == \
                                        '../../le/live/b.com/chain.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'fullchain.pem')) == \
                                        '../../le/live/b.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'privkey.pem')) == \
                                        '../../le/live/b.com/privkey.pem'


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name



def test_2xx_only_already_up():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s, config=s.config7)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config8)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1])

    t_b1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'b.com')
    t_b2 = setup.create_tlsa_obj('212', '12725', 'tcp', 'b.com')
    tb = setup.create_target_obj('b.com', api, [], [t_b1, t_b2])

    assert prog.target_list == [ta, tb]
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'

    assert os.readlink(str(s.dane / 'b.com' / 'cert.pem')) == \
                                        '../../le/live/b.com/cert.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'chain.pem')) == \
                                        '../../le/live/b.com/chain.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'fullchain.pem')) == \
                                        '../../le/live/b.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'privkey.pem')) == \
                                        '../../le/live/b.com/privkey.pem'

    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = { 'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
           'b.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ],
         }

    assert len(prog.dane_domain_directories) == 2
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    assert os.readlink(str(s.dane / 'b.com' / 'cert.pem')) == \
                                        '../../le/archive/b.com/cert1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'chain.pem')) == \
                                        '../../le/archive/b.com/chain1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'fullchain.pem')) == \
                                        '../../le/archive/b.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'privkey.pem')) == \
                                        '../../le/archive/b.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'b.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)



    # first posthook call
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    s.renew_a()
    s.renew_b()
    prog.renewed_domains = [ 'a.com', 'b.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), '--is-up=201:212' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--is-up=201:212", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--is-up=201:212", 201,
                            s.hash['b.com']['cert2'][201]),
            setup.call_line('p', "--is-up=201:212", 212,
                            s.hash['b.com']['cert2'][212]),
            ]
    assert cl == calls


    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'

    assert os.readlink(str(s.dane / 'b.com' / 'cert.pem')) == \
                                        '../../le/live/b.com/cert.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'chain.pem')) == \
                                        '../../le/live/b.com/chain.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'fullchain.pem')) == \
                                        '../../le/live/b.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'b.com' / 'privkey.pem')) == \
                                        '../../le/live/b.com/privkey.pem'


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name




def test_single_renewal_soft_fail():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s, config=s.config2)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config5)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    t_a2 = setup.create_tlsa_obj('211', '12725', 'tcp', 'a.com')
    t_a3 = setup.create_tlsa_obj('301', '12725', 'tcp', 'a.com')
    t_a4 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1, t_a2, t_a3, t_a4])

    assert prog.target_list == [ta]
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'


    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = {'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ]}

    assert len(prog.dane_domain_directories) == 1
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)



    # posthook (certs renewed) -- publish failed
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--fail-publish' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-publish", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--fail-publish", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "--fail-publish", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-publish", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl == calls




    # posthook (ttl passed, no renewal) -- publishing still fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--fail-publish' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # Note: ptime and NOT ptime2: record still not published, so really
    # neither time actually matters...
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-publish", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--fail-publish", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "--fail-publish", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-publish", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[4:] == calls



    # posthook (ttl passed, no renewal) -- 1: publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime3 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--fail-delete' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok
        # publish now succeeds, will not attempt to delete since we've only
        # just managed to publish a record

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-delete", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--fail-delete", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "--fail-delete", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-delete", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[8:] == calls



    # posthook (ttl passed, no renewal) -- 2: publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--fail-delete' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--fail-delete", 201,
                            s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "--fail-delete", 211,
                            s.hash['a.com']['cert1'][211],
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('d', "--fail-delete", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--fail-delete", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[12:] == calls



    # posthook (no renewal, ttl passed)
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [ str(s.bin / 'dns') ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()
     
    calls = [
            setup.call_line('d', "", 201,
                            s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "", 211,
                            s.hash['a.com']['cert1'][211],
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('d', "", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[16:] == calls


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name




def test_single_renewal_2xx_up_soft_fail():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s, config=s.config2)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config5)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    t_a2 = setup.create_tlsa_obj('211', '12725', 'tcp', 'a.com')
    t_a3 = setup.create_tlsa_obj('301', '12725', 'tcp', 'a.com')
    t_a4 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1, t_a2, t_a3, t_a4])

    assert prog.target_list == [ta]
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'


    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = {'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ]}

    assert len(prog.dane_domain_directories) == 1
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)



    # posthook (certs renewed) -- publish failed
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                str(s.bin / 'dns'), '--fail-publish', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-publish --is-up=201:211", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--fail-publish --is-up=201:211", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "--fail-publish --is-up=201:211", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-publish --is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl == calls




    # posthook (ttl passed, no renewal) -- publishing still fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-publish', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # Note: ptime and NOT ptime2: record still not published, so really
    # neither time actually matters...
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-publish --is-up=201:211", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-publish --is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[4:] == calls



    # posthook (ttl passed, no renewal) -- 1: publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime3 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-delete', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok
        # publish now succeeds, will not attempt to delete since we've only
        # just managed to publish a record

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # note: if the 2xx record is already up, then we still write a line
    # because we still need to delete the old record
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-delete --is-up=201:211", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-delete --is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[6:] == calls




    # posthook (ttl passed, no renewal) -- 2: publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-delete', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--fail-delete --is-up=201:211", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--fail-delete --is-up=201:211", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[8:] == calls



    # posthook (no renewal, ttl passed)
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()
     
    calls = [
            setup.call_line('d', "--is-up=201:211", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--is-up=201:211", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[10:] == calls


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name



def test_single_renewal_2xx_delayed_up_soft_fail():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s, config=s.config2)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config5)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    t_a2 = setup.create_tlsa_obj('211', '12725', 'tcp', 'a.com')
    t_a3 = setup.create_tlsa_obj('301', '12725', 'tcp', 'a.com')
    t_a4 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1, t_a2, t_a3, t_a4])

    assert prog.target_list == [ta]
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'


    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = {'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ]}

    assert len(prog.dane_domain_directories) == 1
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)



    # posthook (certs renewed) -- publish failed
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--fail-publish' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-publish", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--fail-publish", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "--fail-publish", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-publish", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl == calls




    # posthook (ttl passed, no renewal) -- publishing still fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-publish', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # Note: ptime and NOT ptime2: record still not published, so really
    # neither time actually matters...
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '1',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-publish --is-up=201:211", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--fail-publish --is-up=201:211", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "--fail-publish --is-up=201:211", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-publish --is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[4:] == calls



    # posthook (ttl passed, no renewal) -- 1: publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime3 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-delete', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok
        # publish now succeeds, will not attempt to delete since we've only
        # just managed to publish a record

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # note: if the 2xx record is already up, then we still write a line
    # because we still need to delete the old record
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-delete --is-up=201:211", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-delete --is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[8:] == calls




    # posthook (ttl passed, no renewal) -- 2: publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-delete', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--fail-delete --is-up=201:211", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--fail-delete --is-up=201:211", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[10:] == calls



    # posthook (no renewal, ttl passed)
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()
     
    calls = [
            setup.call_line('d', "--is-up=201:211", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--is-up=201:211", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[12:] == calls


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name



def test_multi_renewal_soft_fail():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s, config=s.config2)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config5)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    t_a2 = setup.create_tlsa_obj('211', '12725', 'tcp', 'a.com')
    t_a3 = setup.create_tlsa_obj('301', '12725', 'tcp', 'a.com')
    t_a4 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1, t_a2, t_a3, t_a4])

    assert prog.target_list == [ta]
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'


    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = {'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ]}

    assert len(prog.dane_domain_directories) == 1
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)




    # posthook (certs renewed) -- publish succeeds
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [ str(s.bin / 'dns') ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl == calls




    # posthook renewal again, publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--fail-delete' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # no delete lines for 2xx params since the old and new hashes are the
    # same, so the old 'new' certs being up don't need to be deleted: we thus
    # make no delete call
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert3'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert3'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime,
                  '1', s.hash['a.com']['cert2'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '1', s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    # records 2xx are not published again since the new new certs match the
    # old new certs, which were already published successfully
    calls = [
            setup.call_line('p', "--fail-delete", 301,
                            s.hash['a.com']['cert3'][301]),
            setup.call_line('p', "--fail-delete", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "--fail-delete", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--fail-delete", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[4:] == calls






    # posthook renewal again, publish fails, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime3 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-publish', '--fail-delete' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert3'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert3'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime,
                  '2', s.hash['a.com']['cert2'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '2', s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime2,
                  '1', s.hash['a.com']['cert3'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '1', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    # don't forget there's an extra two delete calls to try to delete the
    # previous two delete lines.
    calls = [
            setup.call_line('d', "--fail-publish --fail-delete", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--fail-publish --fail-delete", 311,
                            s.hash['a.com']['cert2'][311]),

            setup.call_line('p', "--fail-publish --fail-delete", 301,
                            s.hash['a.com']['cert1'][301]),
            setup.call_line('p', "--fail-publish --fail-delete", 311,
                            s.hash['a.com']['cert1'][311]),

            setup.call_line('d', "--fail-publish --fail-delete", 301,
                            s.hash['a.com']['cert3'][301]),
            setup.call_line('d', "--fail-publish --fail-delete", 311,
                            s.hash['a.com']['cert3'][311]),
            ]
    assert cl[8:] == calls







    # posthook ttl passed, publish fails, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime4 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-publish', '--fail-delete' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert3'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert3'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime,
                  '3', s.hash['a.com']['cert2'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '3', s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime2,
                  '2', s.hash['a.com']['cert3'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '2', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    # note that ttl has passed and the 2xx records were published at the very
    # beginning (pending state is '0') so right now there is an extra call to
    # delete the 2xx records if the new ones are up
    calls = [
            setup.call_line('d', "--fail-publish --fail-delete", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--fail-publish --fail-delete", 311,
                            s.hash['a.com']['cert2'][311]),

            setup.call_line('d', "--fail-publish --fail-delete", 301,
                            s.hash['a.com']['cert3'][301]),
            setup.call_line('d', "--fail-publish --fail-delete", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "--fail-publish --fail-delete", 201,
                            s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "--fail-publish --fail-delete", 211,
                            s.hash['a.com']['cert1'][211],
                            s.hash['a.com']['cert2'][211]),

            setup.call_line('p', "--fail-publish --fail-delete", 301,
                            s.hash['a.com']['cert1'][301]),
            setup.call_line('p', "--fail-publish --fail-delete", 311,
                            s.hash['a.com']['cert1'][311]),
            ]
    assert cl[14:] == calls






    # posthook ttl passed, publish fails, delete all but 311 not up
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime5 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                        str(s.bin / 'dns'), '--not-up=311', '--fail-publish' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
#                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
#                  s.hash['a.com']['cert3'][201] ],
#                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '0',
#                  s.hash['a.com']['cert3'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][311] ],
#                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime,
#                  '3', s.hash['a.com']['cert2'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '4', s.hash['a.com']['cert2'][311] ],
#                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime2,
#                  '2', s.hash['a.com']['cert3'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '3', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--not-up=311 --fail-publish", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--not-up=311 --fail-publish", 311,
                            s.hash['a.com']['cert2'][311]),

            setup.call_line('d', "--not-up=311 --fail-publish", 301,
                            s.hash['a.com']['cert3'][301]),
            setup.call_line('d', "--not-up=311 --fail-publish", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "--not-up=311 --fail-publish", 201,
                            s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "--not-up=311 --fail-publish", 211,
                            s.hash['a.com']['cert1'][211],
                            s.hash['a.com']['cert2'][211]),

            setup.call_line('p', "--not-up=311 --fail-publish", 301,
                            s.hash['a.com']['cert1'][301]),
            setup.call_line('p', "--not-up=311 --fail-publish", 311,
                            s.hash['a.com']['cert1'][311]),
            ]
    assert cl[22:] == calls





    # posthook renewed again, publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime6 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), '--fail-delete' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # note: the 2xx records are recreated because the certs were renewed again
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime6, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime6, '0',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime6, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime6, '0',
                  s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '5', s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '4', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--fail-delete", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "--fail-delete", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('p', "--fail-delete", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--fail-delete", 211,
                            s.hash['a.com']['cert2'][211]),

            setup.call_line('p', "--fail-delete", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-delete", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[30:] == calls





    # posthook ttl passed, 311 not up
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime7 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), '--not-up=311' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
#                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime6, '0',
#                  s.hash['a.com']['cert2'][201] ],
#                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime6, '0',
#                  s.hash['a.com']['cert2'][211] ],
#                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime6, '0',
#                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime6, '0',
                  s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '6', s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '5', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--not-up=311", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "--not-up=311", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "--not-up=311", 201,
                            s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "--not-up=311", 211,
                            s.hash['a.com']['cert1'][211],
                            s.hash['a.com']['cert2'][211]),

            setup.call_line('d', "--not-up=311", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--not-up=311", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[36:] == calls




    # posthook (no renewal, ttl passed)
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [ str(s.bin / 'dns') ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()
     
    calls = [
            setup.call_line('d', "", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]

    assert cl[42:] == calls


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name



def test_multi_renewal_2xx_up_soft_fail():
    s = setup.Init(keep=True)
    if os.getuid() != 0:
        uid = None
        gid = None
        prog = setup.create_state_obj(s, config=s.config2)
    else:
        uid = pwd.getpwnam('nobody').pw_uid
        gid = None
        prog = setup.create_state_obj(s, config=s.config5)
    cwd = Path.cwd()

    prog.log.init(prog.name, prog.version, prog.timenow)
    assert not prog.log.has_errors()

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    api = setup.create_api_exec_obj(str(s.bin / 'dns'), uid=uid, gid=gid)

    t_a1 = setup.create_tlsa_obj('201', '12725', 'tcp', 'a.com')
    t_a2 = setup.create_tlsa_obj('211', '12725', 'tcp', 'a.com')
    t_a3 = setup.create_tlsa_obj('301', '12725', 'tcp', 'a.com')
    t_a4 = setup.create_tlsa_obj('311', '12725', 'tcp', 'a.com')
    ta = setup.create_target_obj('a.com', api, [], [t_a1, t_a2, t_a3, t_a4])

    assert prog.target_list == [ta]
    assert prog.dane_domain_directories == {}
    assert prog.renewed_domains == []

    retval = main.init_dane_directory(prog)

    assert retval == Prog.RetVal.ok
    assert s.dane.exists()
    assert Path(s.dane / 'a.com').exists()
    assert Path(s.dane / 'b.com').exists()
    assert Path(s.dane / 'c.com').exists()
    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/live/a.com/cert.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/live/a.com/chain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/live/a.com/fullchain.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/live/a.com/privkey.pem'


    retval = main.live_to_archive(prog)

    assert retval == Prog.RetVal.ok

    rd = {'a.com': [ 'cert.pem', 'chain.pem', 'privkey.pem', 'fullchain.pem' ]}

    assert len(prog.dane_domain_directories) == 1
    for d in prog.dane_domain_directories:
        assert sorted(prog.dane_domain_directories[d]) == sorted(rd[d])

    assert os.readlink(str(s.dane / 'a.com' / 'cert.pem')) == \
                                        '../../le/archive/a.com/cert1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'chain.pem')) == \
                                        '../../le/archive/a.com/chain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'fullchain.pem')) == \
                                        '../../le/archive/a.com/fullchain1.pem'
    assert os.readlink(str(s.dane / 'a.com' / 'privkey.pem')) == \
                                        '../../le/archive/a.com/privkey1.pem'

    retval = datafile.write_prehook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 0),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 0),
            ]
    assert sorted(df_lines) == sorted(lines)




    # posthook (certs renewed) -- publish succeeds
    setup.clear_state(prog)
    ptime = "{:%s}".format(prog.timenow)

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime, '0',
                  s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--is-up=201:211", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--is-up=201:211", 211,
                            s.hash['a.com']['cert2'][211]),
            setup.call_line('p', "--is-up=201:211", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl == calls




    # posthook renewal again, publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime2 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                    str(s.bin / 'dns'), '--fail-delete' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert3'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert3'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime,
                  '1', s.hash['a.com']['cert2'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '1', s.hash['a.com']['cert2'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('p', "--fail-delete", 201,
                            s.hash['a.com']['cert3'][201]),
            setup.call_line('p', "--fail-delete", 211,
                            s.hash['a.com']['cert3'][211]),
            setup.call_line('p', "--fail-delete", 301,
                            s.hash['a.com']['cert3'][301]),
            setup.call_line('p', "--fail-delete", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "--fail-delete", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--fail-delete", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[4:] == calls





    # posthook renewal again, publish fails, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime3 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
            str(s.bin / 'dns'), '--fail-publish', '--fail-delete',
            '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # note: 2xx posthook lines not deleted because they were already
    # previously published and the renewed certs do not change the 2xx hashes,
    # so rather than attempting to publish again, the posthook lines' times
    # are just updated (so the lines will still exist)
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime,
                  '2', s.hash['a.com']['cert2'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '2', s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime2,
                  '1', s.hash['a.com']['cert3'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '1', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    # don't forget there's an extra two delete calls to try to delete the
    # previous two delete lines.
    calls = [
            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            301, s.hash['a.com']['cert2'][301]),
            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            311, s.hash['a.com']['cert2'][311]),

            setup.call_line('p',
                            "--fail-publish --fail-delete --is-up=201:211",
                            301, s.hash['a.com']['cert1'][301]),
            setup.call_line('p',
                            "--fail-publish --fail-delete --is-up=201:211",
                            311, s.hash['a.com']['cert1'][311]),

            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            301, s.hash['a.com']['cert3'][301]),
            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            311, s.hash['a.com']['cert3'][311]),
            ]
    assert cl[10:] == calls






    # posthook ttl passed, publish fails, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime4 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-publish', '--fail-delete',
                    '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert2'][201] ],
                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime2, '0',
                  s.hash['a.com']['cert2'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime,
                  '3', s.hash['a.com']['cert2'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '3', s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime2,
                  '2', s.hash['a.com']['cert3'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '2', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    # note that ttl has passed and the 2xx records were published at the very
    # beginning (pending state is '0') so right now there is an extra call to
    # delete the 2xx records if the new ones are up
    calls = [
            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            301, s.hash['a.com']['cert2'][301]),
            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            311, s.hash['a.com']['cert2'][311]),

            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            301, s.hash['a.com']['cert3'][301]),
            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            311, s.hash['a.com']['cert3'][311]),

            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            201, s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d',
                            "--fail-publish --fail-delete --is-up=201:211",
                            211, s.hash['a.com']['cert1'][211],
                            s.hash['a.com']['cert2'][211]),

            setup.call_line('p',
                            "--fail-publish --fail-delete --is-up=201:211",
                            301, s.hash['a.com']['cert1'][301]),
            setup.call_line('p',
                            "--fail-publish --fail-delete --is-up=201:211",
                            311, s.hash['a.com']['cert1'][311]),
            ]
    assert cl[16:] == calls






    # posthook ttl passed, publish fails, delete all but 311 not up
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime5 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                str(s.bin / 'dns'), '--not-up=311', '--fail-publish',
                '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
#                [ 'a.com', '201', '12725', 'tcp', 'a.com', ptime, '0',
#                  s.hash['a.com']['cert3'][201] ],
#                [ 'a.com', '211', '12725', 'tcp', 'a.com', ptime, '0',
#                  s.hash['a.com']['cert3'][211] ],
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime3, '1',
                  s.hash['a.com']['cert1'][311] ],
#                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime,
#                  '3', s.hash['a.com']['cert2'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '4', s.hash['a.com']['cert2'][311] ],
#                [ 'a.com', 'delete', '301', '12725', 'tcp', 'a.com', ptime2,
#                  '2', s.hash['a.com']['cert3'][301] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '3', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--not-up=311 --fail-publish --is-up=201:211",
                            301, s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--not-up=311 --fail-publish --is-up=201:211",
                            311, s.hash['a.com']['cert2'][311]),

            setup.call_line('d', "--not-up=311 --fail-publish --is-up=201:211",
                            301, s.hash['a.com']['cert3'][301]),
            setup.call_line('d', "--not-up=311 --fail-publish --is-up=201:211",
                            311, s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "--not-up=311 --fail-publish --is-up=201:211",
                            201, s.hash['a.com']['cert1'][201],
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('d', "--not-up=311 --fail-publish --is-up=201:211",
                            211, s.hash['a.com']['cert1'][211],
                            s.hash['a.com']['cert2'][211]),

            setup.call_line('p', "--not-up=311 --fail-publish --is-up=201:211",
                            301, s.hash['a.com']['cert1'][301]),
            setup.call_line('p', "--not-up=311 --fail-publish --is-up=201:211",
                            311, s.hash['a.com']['cert1'][311]),
            ]
    assert cl[24:] == calls





    # posthook renewed again, publish succeeds, delete fails
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime6 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    s.renew_a()
    prog.renewed_domains = [ 'a.com' ]

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                    str(s.bin / 'dns'), '--fail-delete', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.continue_failure

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    # note: the 2xx records would be recreated because the certs were
    # renewed again, but because they are already up (binary 'dns' returns
    # '1') their processing is considered done and no posthook lines are
    # written.
    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '301', '12725', 'tcp', 'a.com', ptime6, '0',
                  s.hash['a.com']['cert2'][301] ],
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime6, '0',
                  s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '5', s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '4', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--fail-delete --is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "--fail-delete --is-up=201:211", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('p', "--fail-delete --is-up=201:211", 201,
                            s.hash['a.com']['cert2'][201]),
            setup.call_line('p', "--fail-delete --is-up=201:211", 211,
                            s.hash['a.com']['cert2'][211]),

            setup.call_line('p', "--fail-delete --is-up=201:211", 301,
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('p', "--fail-delete --is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[32:] == calls





    # posthook ttl passed, 311 not up
    sleep(sleep_time)
    setup.clear_state(prog)
    ptime7 = "{:%s}".format(prog.timenow)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                        str(s.bin / 'dns'), '--not-up=311', '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    with open(str(prog.datafile), 'r') as file:
        df = file.read().splitlines()

    df_lines = []
    for k in df[2:]:
        df_lines += [ shlex.split(k) ]

    lines = [
                setup.prehook_line(s, cwd, 'a.com', 'cert1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'chain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'fullchain1.pem', 1),
                setup.prehook_line(s, cwd, 'a.com', 'privkey1.pem', 1),
                [ 'a.com', '311', '12725', 'tcp', 'a.com', ptime6, '0',
                  s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime,
                  '6', s.hash['a.com']['cert2'][311] ],
                [ 'a.com', 'delete', '311', '12725', 'tcp', 'a.com', ptime2,
                  '5', s.hash['a.com']['cert3'][311] ],
            ]
    assert sorted(df_lines) == sorted(lines)

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--not-up=311 --is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "--not-up=311 --is-up=201:211", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "--not-up=311 --is-up=201:211", 301,
                            s.hash['a.com']['cert1'][301],
                            s.hash['a.com']['cert2'][301]),
            setup.call_line('d', "--not-up=311 --is-up=201:211", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]
    assert cl[38:] == calls




    # posthook (no renewal, ttl passed)
    sleep(sleep_time)
    setup.clear_state(prog)
    prog.ttl = 0

    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.read(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.check_data(prog)
    assert retval == Prog.RetVal.ok

    prog.data.groups[0].target.api.command = [
                                        str(s.bin / 'dns'), '--is-up=201:211' ]

    retval = main.process_data(prog)
    assert retval == Prog.RetVal.ok

    retval = datafile.write_posthook(prog)
    assert retval == Prog.RetVal.ok

    assert not prog.datafile.exists()

    with open(str(s.data / 'calls'), 'r') as file:
        cl = file.read().splitlines()

    calls = [
            setup.call_line('d', "--is-up=201:211", 311,
                            s.hash['a.com']['cert2'][311]),
            setup.call_line('d', "--is-up=201:211", 311,
                            s.hash['a.com']['cert3'][311]),

            setup.call_line('d', "--is-up=201:211", 311,
                            s.hash['a.com']['cert1'][311],
                            s.hash['a.com']['cert2'][311]),
            ]

    assert cl[42:] == calls


    with open(str(s.data / 'user'), 'r') as f:
        whodata = f.read().splitlines()

    if os.getuid() == 0:
        for wd in whodata:
            assert wd[0:7] == "nobody:"
    else:
        name = pwd.getpwuid(os.getuid()).pw_name
        namelen = len(name)
        for wd in whodata:
            assert wd[0:namelen] == name




