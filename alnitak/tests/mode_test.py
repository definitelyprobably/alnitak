
import pwd
import os
import shutil
from pathlib import Path

from alnitak.tests import setup
from alnitak import state
from alnitak import mode

# FIXME: add check for target['prepared']
# FIXME: add uid checks if run as root

# need to check scenarios:
#   1. ippd
#   pprddDD
#   pprrddDD
#   pprrddrrddDD
#   dd
#
# then also need to check prepare mode handling a previous state:
#   prppdd
#     ^
#   prdpdd
#      ^
#   etc.


def test_mode_1():
    '''
    ippd
    '''

    # create testing directory
    le = setup.create_testing_base_dir()

    # define alnitak directory
    al = le.parent / 'al'

    # remove alnitak directory, if present
    if al.exists():
        shutil.rmtree(str(al))

    # create state object
    s = state.State()

    # skip the chmod code
    if os.getuid() != 0:
        s.testing_mode = True

    # use the setup handler to capture errors/warnings
    s.handler = setup.Handler()

    s.create_target('a.com')
    s.set_letsencrypt_directory('a.com', le)
    s.set_dane_directory('a.com', al)

    s.create_target('b.com')
    s.set_letsencrypt_directory('b.com', le)
    s.set_dane_directory('b.com', al)

    s.create_target('c.com')
    s.set_letsencrypt_directory('c.com', le)
    s.set_dane_directory('c.com', al)

    s.create_record('a.com', '3', '1', '1', '25', 'tcp')
    s.create_record('a.com', '3', '1', '1', '25', 'tcp', 'a1.a.com')

    s.create_record('b.com', '3', '1', '2', '443', 'tcp')
    s.create_record('b.com', '2', '0', '0', '1234', 'abcp', 'b.b.com')

    s.create_record('c.com', '3', '1', '2', '1000', 'udp')
    s.create_record('c.com', '3', '0', '1', '1001', 'sctp', 'c1.c.com')

    s.create_api_exec('a.com', [ '.alnitak_tests/bin/api' ])
    s.create_api_exec('b.com', [ '.alnitak_tests/bin/api' ])
    s.create_api_exec('c.com', [ '.alnitak_tests/bin/api' ])


    # INIT call -- DD sould be links to live. No errors.
    s.set_call_init()
    mode.prepare(s)

    # check state is correct
    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'init'

    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    assert s.targets['a.com']['progress'] == 'prepared'
    assert s.targets['b.com']['progress'] == 'prepared'
    assert s.targets['c.com']['progress'] == 'prepared'

    assert s.targets['a.com']['prepared'] == True
    assert s.targets['b.com']['prepared'] == True
    assert s.targets['c.com']['prepared'] == True

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'a.com',
            ad = le / 'archive',
            add = le / 'archive' / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'a.com' / 'cert.pem',
                'archive': le / 'archive' / 'a.com' / 'cert1.pem',
                'dane': al / 'a.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'a.com' / 'chain.pem',
                'archive': le / 'archive' / 'a.com' / 'chain1.pem',
                'dane': al / 'a.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'a.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'a.com' / 'fullchain1.pem',
                'dane': al / 'a.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'a.com' / 'privkey.pem',
                'archive': le / 'archive' / 'a.com' / 'privkey1.pem',
                'dane': al / 'a.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al,
            san = False,
            ddd = al / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'b.com',
            ad = le / 'archive',
            add = le / 'archive' / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'b.com' / 'cert.pem',
                'archive': le / 'archive' / 'b.com' / 'cert1.pem',
                'dane': al / 'b.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'b.com' / 'chain.pem',
                'archive': le / 'archive' / 'b.com' / 'chain1.pem',
                'dane': al / 'b.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'b.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'b.com' / 'fullchain1.pem',
                'dane': al / 'b.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'b.com' / 'privkey.pem',
                'archive': le / 'archive' / 'b.com' / 'privkey1.pem',
                'dane': al / 'b.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al,
            san = False,
            ddd = al / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'c.com',
            ad = le / 'archive',
            add = le / 'archive' / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'c.com' / 'cert.pem',
                'archive': le / 'archive' / 'c.com' / 'cert1.pem',
                'dane': al / 'c.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'c.com' / 'chain.pem',
                'archive': le / 'archive' / 'c.com' / 'chain1.pem',
                'dane': al / 'c.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'c.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'c.com' / 'fullchain1.pem',
                'dane': al / 'c.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'c.com' / 'privkey.pem',
                'archive': le / 'archive' / 'c.com' / 'privkey1.pem',
                'dane': al / 'c.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False

    setup.check_record(s, 'a.com', '311', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '311', '25', 'tcp', rdomain='a1.a.com')

    setup.check_record(s, 'b.com', '312', '443', 'tcp', rdomain='b.com')
    setup.check_record(s, 'b.com', '200', '1234', 'abcp', rdomain='b.b.com')

    setup.check_record(s, 'c.com', '312', '1000', 'udp', rdomain='c.com')
    setup.check_record(s, 'c.com', '301', '1001', 'sctp', rdomain='c1.c.com')

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')


    setup.exists_and_is_file( al / 'a.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'cert.pem') )
                == '../../le/live/a.com/cert.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'chain.pem') )
                == '../../le/live/a.com/chain.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'fullchain.pem') )
                == '../../le/live/a.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'privkey.pem') )
                == '../../le/live/a.com/privkey.pem' )

    setup.exists_and_is_file( al / 'b.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'cert.pem') )
                == '../../le/live/b.com/cert.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'chain.pem') )
                == '../../le/live/b.com/chain.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'fullchain.pem') )
                == '../../le/live/b.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'privkey.pem') )
                == '../../le/live/b.com/privkey.pem' )

    setup.exists_and_is_file( al / 'c.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'cert.pem') )
                == '../../le/live/c.com/cert.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'chain.pem') )
                == '../../le/live/c.com/chain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'fullchain.pem') )
                == '../../le/live/c.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'privkey.pem') )
                == '../../le/live/c.com/privkey.pem' )


    # PREPARE call -- DD should be to archive. No errors.
    s.set_call_prepare()
    s.renewed_domains = [] # unset renewed domains
    mode.prepare(s)

    # check state is correct
    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'prepare'

    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    assert s.targets['a.com']['progress'] == 'prepared'
    assert s.targets['b.com']['progress'] == 'prepared'
    assert s.targets['c.com']['progress'] == 'prepared'

    assert s.targets['a.com']['prepared'] == True
    assert s.targets['b.com']['prepared'] == True
    assert s.targets['c.com']['prepared'] == True

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'a.com',
            ad = le / 'archive',
            add = le / 'archive' / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'a.com' / 'cert.pem',
                'archive': le / 'archive' / 'a.com' / 'cert1.pem',
                'dane': al / 'a.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'a.com' / 'chain.pem',
                'archive': le / 'archive' / 'a.com' / 'chain1.pem',
                'dane': al / 'a.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'a.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'a.com' / 'fullchain1.pem',
                'dane': al / 'a.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'a.com' / 'privkey.pem',
                'archive': le / 'archive' / 'a.com' / 'privkey1.pem',
                'dane': al / 'a.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al,
            san = False,
            ddd = al / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'b.com',
            ad = le / 'archive',
            add = le / 'archive' / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'b.com' / 'cert.pem',
                'archive': le / 'archive' / 'b.com' / 'cert1.pem',
                'dane': al / 'b.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'b.com' / 'chain.pem',
                'archive': le / 'archive' / 'b.com' / 'chain1.pem',
                'dane': al / 'b.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'b.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'b.com' / 'fullchain1.pem',
                'dane': al / 'b.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'b.com' / 'privkey.pem',
                'archive': le / 'archive' / 'b.com' / 'privkey1.pem',
                'dane': al / 'b.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al,
            san = False,
            ddd = al / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'c.com',
            ad = le / 'archive',
            add = le / 'archive' / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'c.com' / 'cert.pem',
                'archive': le / 'archive' / 'c.com' / 'cert1.pem',
                'dane': al / 'c.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'c.com' / 'chain.pem',
                'archive': le / 'archive' / 'c.com' / 'chain1.pem',
                'dane': al / 'c.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'c.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'c.com' / 'fullchain1.pem',
                'dane': al / 'c.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'c.com' / 'privkey.pem',
                'archive': le / 'archive' / 'c.com' / 'privkey1.pem',
                'dane': al / 'c.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False

    setup.check_record(s, 'a.com', '311', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '311', '25', 'tcp', rdomain='a1.a.com')

    setup.check_record(s, 'b.com', '312', '443', 'tcp', rdomain='b.com')
    setup.check_record(s, 'b.com', '200', '1234', 'abcp', rdomain='b.b.com')

    setup.check_record(s, 'c.com', '312', '1000', 'udp', rdomain='c.com')
    setup.check_record(s, 'c.com', '301', '1001', 'sctp', rdomain='c1.c.com')

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')


    setup.exists_and_is_file( al / 'a.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'cert.pem') )
                == '../../le/archive/a.com/cert1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'chain.pem') )
                == '../../le/archive/a.com/chain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'fullchain.pem') )
                == '../../le/archive/a.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'privkey.pem') )
                == '../../le/archive/a.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'b.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'cert.pem') )
                == '../../le/archive/b.com/cert1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'chain.pem') )
                == '../../le/archive/b.com/chain1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'fullchain.pem') )
                == '../../le/archive/b.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'privkey.pem') )
                == '../../le/archive/b.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'c.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'cert.pem') )
                == '../../le/archive/c.com/cert1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'chain.pem') )
                == '../../le/archive/c.com/chain1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'fullchain.pem') )
                == '../../le/archive/c.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'privkey.pem') )
                == '../../le/archive/c.com/privkey1.pem' )


    # PREPARE call -- DD should be to archive. No errors.
    s.set_call_prepare()
    s.renewed_domains = [] # unset renewed domains
    mode.prepare(s)

    # check state is correct
    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'prepare'

    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    assert s.targets['a.com']['progress'] == 'prepared'
    assert s.targets['b.com']['progress'] == 'prepared'
    assert s.targets['c.com']['progress'] == 'prepared'

    assert s.targets['a.com']['prepared'] == True
    assert s.targets['b.com']['prepared'] == True
    assert s.targets['c.com']['prepared'] == True

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'a.com',
            ad = le / 'archive',
            add = le / 'archive' / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'a.com' / 'cert.pem',
                'archive': le / 'archive' / 'a.com' / 'cert1.pem',
                'dane': al / 'a.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'a.com' / 'chain.pem',
                'archive': le / 'archive' / 'a.com' / 'chain1.pem',
                'dane': al / 'a.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'a.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'a.com' / 'fullchain1.pem',
                'dane': al / 'a.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'a.com' / 'privkey.pem',
                'archive': le / 'archive' / 'a.com' / 'privkey1.pem',
                'dane': al / 'a.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al,
            san = False,
            ddd = al / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'b.com',
            ad = le / 'archive',
            add = le / 'archive' / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'b.com' / 'cert.pem',
                'archive': le / 'archive' / 'b.com' / 'cert1.pem',
                'dane': al / 'b.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'b.com' / 'chain.pem',
                'archive': le / 'archive' / 'b.com' / 'chain1.pem',
                'dane': al / 'b.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'b.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'b.com' / 'fullchain1.pem',
                'dane': al / 'b.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'b.com' / 'privkey.pem',
                'archive': le / 'archive' / 'b.com' / 'privkey1.pem',
                'dane': al / 'b.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al,
            san = False,
            ddd = al / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'c.com',
            ad = le / 'archive',
            add = le / 'archive' / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'c.com' / 'cert.pem',
                'archive': le / 'archive' / 'c.com' / 'cert1.pem',
                'dane': al / 'c.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'c.com' / 'chain.pem',
                'archive': le / 'archive' / 'c.com' / 'chain1.pem',
                'dane': al / 'c.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'c.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'c.com' / 'fullchain1.pem',
                'dane': al / 'c.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'c.com' / 'privkey.pem',
                'archive': le / 'archive' / 'c.com' / 'privkey1.pem',
                'dane': al / 'c.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False

    setup.check_record(s, 'a.com', '311', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '311', '25', 'tcp', rdomain='a1.a.com')

    setup.check_record(s, 'b.com', '312', '443', 'tcp', rdomain='b.com')
    setup.check_record(s, 'b.com', '200', '1234', 'abcp', rdomain='b.b.com')

    setup.check_record(s, 'c.com', '312', '1000', 'udp', rdomain='c.com')
    setup.check_record(s, 'c.com', '301', '1001', 'sctp', rdomain='c1.c.com')

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')


    setup.exists_and_is_file( al / 'a.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'cert.pem') )
                == '../../le/archive/a.com/cert1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'chain.pem') )
                == '../../le/archive/a.com/chain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'fullchain.pem') )
                == '../../le/archive/a.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'privkey.pem') )
                == '../../le/archive/a.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'b.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'cert.pem') )
                == '../../le/archive/b.com/cert1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'chain.pem') )
                == '../../le/archive/b.com/chain1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'fullchain.pem') )
                == '../../le/archive/b.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'privkey.pem') )
                == '../../le/archive/b.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'c.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'cert.pem') )
                == '../../le/archive/c.com/cert1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'chain.pem') )
                == '../../le/archive/c.com/chain1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'fullchain.pem') )
                == '../../le/archive/c.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'privkey.pem') )
                == '../../le/archive/c.com/privkey1.pem' )


    # DEPLOY CALL -- DD should be back to live. No errors.
    s.set_call_deploy()
    s.renewed_domains = [] # unset renewed domains
    mode.deploy(s)

    # check state is correct
    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'deploy'

    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    assert s.targets['a.com']['progress'] == 'unprepared'
    assert s.targets['b.com']['progress'] == 'unprepared'
    assert s.targets['c.com']['progress'] == 'unprepared'

    assert s.targets['a.com']['prepared'] == True
    assert s.targets['b.com']['prepared'] == True
    assert s.targets['c.com']['prepared'] == True

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'a.com',
            ad = le / 'archive',
            add = le / 'archive' / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'a.com' / 'cert.pem',
                'archive': le / 'archive' / 'a.com' / 'cert1.pem',
                'dane': al / 'a.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'a.com' / 'chain.pem',
                'archive': le / 'archive' / 'a.com' / 'chain1.pem',
                'dane': al / 'a.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'a.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'a.com' / 'fullchain1.pem',
                'dane': al / 'a.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'a.com' / 'privkey.pem',
                'archive': le / 'archive' / 'a.com' / 'privkey1.pem',
                'dane': al / 'a.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al,
            san = False,
            ddd = al / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'b.com',
            ad = le / 'archive',
            add = le / 'archive' / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'b.com' / 'cert.pem',
                'archive': le / 'archive' / 'b.com' / 'cert1.pem',
                'dane': al / 'b.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'b.com' / 'chain.pem',
                'archive': le / 'archive' / 'b.com' / 'chain1.pem',
                'dane': al / 'b.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'b.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'b.com' / 'fullchain1.pem',
                'dane': al / 'b.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'b.com' / 'privkey.pem',
                'archive': le / 'archive' / 'b.com' / 'privkey1.pem',
                'dane': al / 'b.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al,
            san = False,
            ddd = al / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'c.com',
            ad = le / 'archive',
            add = le / 'archive' / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'c.com' / 'cert.pem',
                'archive': le / 'archive' / 'c.com' / 'cert1.pem',
                'dane': al / 'c.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'c.com' / 'chain.pem',
                'archive': le / 'archive' / 'c.com' / 'chain1.pem',
                'dane': al / 'c.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'c.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'c.com' / 'fullchain1.pem',
                'dane': al / 'c.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'c.com' / 'privkey.pem',
                'archive': le / 'archive' / 'c.com' / 'privkey1.pem',
                'dane': al / 'c.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False

    setup.check_record(s, 'a.com', '311', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '311', '25', 'tcp', rdomain='a1.a.com')

    setup.check_record(s, 'b.com', '312', '443', 'tcp', rdomain='b.com')
    setup.check_record(s, 'b.com', '200', '1234', 'abcp', rdomain='b.b.com')

    setup.check_record(s, 'c.com', '312', '1000', 'udp', rdomain='c.com')
    setup.check_record(s, 'c.com', '301', '1001', 'sctp', rdomain='c1.c.com')

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')


    setup.exists_and_is_file( al / 'a.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'cert.pem') )
                == '../../le/live/a.com/cert.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'chain.pem') )
                == '../../le/live/a.com/chain.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'fullchain.pem') )
                == '../../le/live/a.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'privkey.pem') )
                == '../../le/live/a.com/privkey.pem' )

    setup.exists_and_is_file( al / 'b.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'cert.pem') )
                == '../../le/live/b.com/cert.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'chain.pem') )
                == '../../le/live/b.com/chain.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'fullchain.pem') )
                == '../../le/live/b.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'privkey.pem') )
                == '../../le/live/b.com/privkey.pem' )

    setup.exists_and_is_file( al / 'c.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'cert.pem') )
                == '../../le/live/c.com/cert.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'chain.pem') )
                == '../../le/live/c.com/chain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'fullchain.pem') )
                == '../../le/live/c.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'privkey.pem') )
                == '../../le/live/c.com/privkey.pem' )


def test_mode_2():
    '''
    iprddDD
    '''

    # create testing directory
    le = setup.create_testing_base_dir()

    # create exec bin
    call_data = setup.create_exec()

    # define alnitak directory
    al = le.parent / 'al'

    # remove alnitak directory, if present
    if al.exists():
        shutil.rmtree(str(al))

    # create state object
    s = state.State()

    # skip the chmod code
    if os.getuid() != 0:
        s.testing_mode = True

    # use the setup handler to capture errors/warnings
    s.handler = setup.Handler()

    s.create_target('a.com')
    s.set_letsencrypt_directory('a.com', le)
    s.set_dane_directory('a.com', al)

    s.create_target('b.com')
    s.set_letsencrypt_directory('b.com', le)
    s.set_dane_directory('b.com', al)

    s.create_target('c.com')
    s.set_letsencrypt_directory('c.com', le)
    s.set_dane_directory('c.com', al)

    # some records are up, delete fails
    s.create_record('a.com', '2', '0', '0', '25', 'tcp')
    s.create_record('a.com', '2', '0', '1', '25', 'tcp')
    s.create_record('a.com', '2', '0', '2', '25', 'tcp')
    s.create_record('a.com', '3', '0', '1', '25', 'tcp')
    s.create_record('a.com', '3', '0', '1', '2525', 'tcp')
    s.create_record('a.com', '3', '0', '1', '25', 'tcp', 'a.a.com')

    # some records are up, delete works
    s.create_record('b.com', '2', '1', '1', '443', 'tcp')
    s.create_record('b.com', '3', '1', '1', '1234', 'abcp', 'b.b.com')
    s.create_record('b.com', '3', '1', '2', '5678', 'xyz', 'b1.b.com')

    # all records are already up
    s.create_record('c.com', '3', '0', '0', '1000', 'udp')
    s.create_record('c.com', '3', '0', '1', '1001', 'sctp', 'c1.c.com')
    s.create_record('c.com', '3', '0', '2', '1002', 'tcp', 'c2.c.com')

    s.create_api_exec('a.com',
            [ '.alnitak_tests/bin/api', '200::1',
                                        'publish:a.com:301:25:tcp:a.com::1' ],
            uid=pwd.getpwnam('nobody').pw_uid)
    s.create_api_exec('b.com',
            [ '.alnitak_tests/bin/api', '211::1' ],
            uid=pwd.getpwnam('nobody').pw_uid)
    s.create_api_exec('c.com',
            [ '.alnitak_tests/bin/api', 'publish::1' ],
            uid=pwd.getpwnam('nobody').pw_uid)


    # INIT call -- DD sould be links to live. No errors.
    s.set_call_init()
    mode.prepare(s)

    # check state is correct
    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'init'

    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    assert s.targets['a.com']['progress'] == 'prepared'
    assert s.targets['b.com']['progress'] == 'prepared'
    assert s.targets['c.com']['progress'] == 'prepared'

    assert s.targets['a.com']['prepared'] == True
    assert s.targets['b.com']['prepared'] == True
    assert s.targets['c.com']['prepared'] == True

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'a.com',
            ad = le / 'archive',
            add = le / 'archive' / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'a.com' / 'cert.pem',
                'archive': le / 'archive' / 'a.com' / 'cert1.pem',
                'dane': al / 'a.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'a.com' / 'chain.pem',
                'archive': le / 'archive' / 'a.com' / 'chain1.pem',
                'dane': al / 'a.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'a.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'a.com' / 'fullchain1.pem',
                'dane': al / 'a.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'a.com' / 'privkey.pem',
                'archive': le / 'archive' / 'a.com' / 'privkey1.pem',
                'dane': al / 'a.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al,
            san = False,
            ddd = al / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'b.com',
            ad = le / 'archive',
            add = le / 'archive' / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'b.com' / 'cert.pem',
                'archive': le / 'archive' / 'b.com' / 'cert1.pem',
                'dane': al / 'b.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'b.com' / 'chain.pem',
                'archive': le / 'archive' / 'b.com' / 'chain1.pem',
                'dane': al / 'b.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'b.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'b.com' / 'fullchain1.pem',
                'dane': al / 'b.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'b.com' / 'privkey.pem',
                'archive': le / 'archive' / 'b.com' / 'privkey1.pem',
                'dane': al / 'b.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al,
            san = False,
            ddd = al / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'c.com',
            ad = le / 'archive',
            add = le / 'archive' / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'c.com' / 'cert.pem',
                'archive': le / 'archive' / 'c.com' / 'cert1.pem',
                'dane': al / 'c.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'c.com' / 'chain.pem',
                'archive': le / 'archive' / 'c.com' / 'chain1.pem',
                'dane': al / 'c.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'c.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'c.com' / 'fullchain1.pem',
                'dane': al / 'c.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'c.com' / 'privkey.pem',
                'archive': le / 'archive' / 'c.com' / 'privkey1.pem',
                'dane': al / 'c.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False

    setup.check_record(s, 'a.com', '200', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '201', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '202', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '301', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '301', '2525', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '301', '25', 'tcp', rdomain='a.a.com')

    setup.check_record(s, 'b.com', '211', '443', 'tcp', rdomain='b.com')
    setup.check_record(s, 'b.com', '311', '1234', 'abcp', rdomain='b.b.com')
    setup.check_record(s, 'b.com', '312', '5678', 'xyz', rdomain='b1.b.com')

    setup.check_record(s, 'c.com', '300', '1000', 'udp', rdomain='c.com')
    setup.check_record(s, 'c.com', '301', '1001', 'sctp', rdomain='c1.c.com')
    setup.check_record(s, 'c.com', '302', '1002', 'tcp', rdomain='c2.c.com')

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')


    setup.exists_and_is_file( al / 'a.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'cert.pem') )
                == '../../le/live/a.com/cert.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'chain.pem') )
                == '../../le/live/a.com/chain.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'fullchain.pem') )
                == '../../le/live/a.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'privkey.pem') )
                == '../../le/live/a.com/privkey.pem' )

    setup.exists_and_is_file( al / 'b.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'cert.pem') )
                == '../../le/live/b.com/cert.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'chain.pem') )
                == '../../le/live/b.com/chain.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'fullchain.pem') )
                == '../../le/live/b.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'privkey.pem') )
                == '../../le/live/b.com/privkey.pem' )

    setup.exists_and_is_file( al / 'c.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'cert.pem') )
                == '../../le/live/c.com/cert.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'chain.pem') )
                == '../../le/live/c.com/chain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'fullchain.pem') )
                == '../../le/live/c.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'privkey.pem') )
                == '../../le/live/c.com/privkey.pem' )


    # PREPARE call -- DD should be to archive. No errors.
    s.set_call_prepare()
    s.renewed_domains = [] # unset renewed domains
    mode.prepare(s)

    # check state is correct
    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'prepare'

    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    assert s.targets['a.com']['progress'] == 'prepared'
    assert s.targets['b.com']['progress'] == 'prepared'
    assert s.targets['c.com']['progress'] == 'prepared'

    assert s.targets['a.com']['prepared'] == True
    assert s.targets['b.com']['prepared'] == True
    assert s.targets['c.com']['prepared'] == True

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'a.com',
            ad = le / 'archive',
            add = le / 'archive' / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'a.com' / 'cert.pem',
                'archive': le / 'archive' / 'a.com' / 'cert1.pem',
                'dane': al / 'a.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'a.com' / 'chain.pem',
                'archive': le / 'archive' / 'a.com' / 'chain1.pem',
                'dane': al / 'a.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'a.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'a.com' / 'fullchain1.pem',
                'dane': al / 'a.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'a.com' / 'privkey.pem',
                'archive': le / 'archive' / 'a.com' / 'privkey1.pem',
                'dane': al / 'a.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al,
            san = False,
            ddd = al / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'b.com',
            ad = le / 'archive',
            add = le / 'archive' / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'b.com' / 'cert.pem',
                'archive': le / 'archive' / 'b.com' / 'cert1.pem',
                'dane': al / 'b.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'b.com' / 'chain.pem',
                'archive': le / 'archive' / 'b.com' / 'chain1.pem',
                'dane': al / 'b.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'b.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'b.com' / 'fullchain1.pem',
                'dane': al / 'b.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'b.com' / 'privkey.pem',
                'archive': le / 'archive' / 'b.com' / 'privkey1.pem',
                'dane': al / 'b.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al,
            san = False,
            ddd = al / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'c.com',
            ad = le / 'archive',
            add = le / 'archive' / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'c.com' / 'cert.pem',
                'archive': le / 'archive' / 'c.com' / 'cert1.pem',
                'dane': al / 'c.com' / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': le / 'live' / 'c.com' / 'chain.pem',
                'archive': le / 'archive' / 'c.com' / 'chain1.pem',
                'dane': al / 'c.com' / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': le / 'live' / 'c.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'c.com' / 'fullchain1.pem',
                'dane': al / 'c.com' / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': le / 'live' / 'c.com' / 'privkey.pem',
                'archive': le / 'archive' / 'c.com' / 'privkey1.pem',
                'dane': al / 'c.com' / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False

    setup.check_record(s, 'a.com', '200', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '201', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '202', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '301', '25', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '301', '2525', 'tcp', rdomain='a.com')
    setup.check_record(s, 'a.com', '301', '25', 'tcp', rdomain='a.a.com')

    setup.check_record(s, 'b.com', '211', '443', 'tcp', rdomain='b.com')
    setup.check_record(s, 'b.com', '311', '1234', 'abcp', rdomain='b.b.com')
    setup.check_record(s, 'b.com', '312', '5678', 'xyz', rdomain='b1.b.com')

    setup.check_record(s, 'c.com', '300', '1000', 'udp', rdomain='c.com')
    setup.check_record(s, 'c.com', '301', '1001', 'sctp', rdomain='c1.c.com')
    setup.check_record(s, 'c.com', '302', '1002', 'tcp', rdomain='c2.c.com')

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')


    setup.exists_and_is_file( al / 'a.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'cert.pem') )
                == '../../le/archive/a.com/cert1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'chain.pem') )
                == '../../le/archive/a.com/chain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'fullchain.pem') )
                == '../../le/archive/a.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'privkey.pem') )
                == '../../le/archive/a.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'b.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'cert.pem') )
                == '../../le/archive/b.com/cert1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'chain.pem') )
                == '../../le/archive/b.com/chain1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'fullchain.pem') )
                == '../../le/archive/b.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'privkey.pem') )
                == '../../le/archive/b.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'c.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'cert.pem') )
                == '../../le/archive/c.com/cert1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'chain.pem') )
                == '../../le/archive/c.com/chain1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'fullchain.pem') )
                == '../../le/archive/c.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'privkey.pem') )
                == '../../le/archive/c.com/privkey1.pem' )


    # DEPLOY CALL -- All domains renewed. No errors.
    # all records published, c.com all were already up, a.com and b.com had
    # some up already.
    setup.simulate_renew()
    s.set_call_deploy()
    s.renewed_domains = [] # unset renewed domains
    mode.deploy(s)

    # check state is correct
    assert 'a.com' in s.renewed_domains
    assert 'b.com' in s.renewed_domains
    assert 'c.com' in s.renewed_domains
    assert len(s.renewed_domains) == 3
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'deploy'

    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    assert s.targets['a.com']['progress'] == 'deployed'
    assert s.targets['b.com']['progress'] == 'deployed'
    assert s.targets['c.com']['progress'] == 'unprepared'

    assert s.targets['a.com']['prepared'] == True
    assert s.targets['b.com']['prepared'] == True
    assert s.targets['c.com']['prepared'] == True

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'a.com',
            ad = le / 'archive',
            add = le / 'archive' / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'a.com' / 'cert.pem',
                'archive': le / 'archive' / 'a.com' / 'cert1.pem',
                'dane': al / 'a.com' / 'cert.pem',
                'renew': le / 'archive' / 'a.com' / 'cert2.pem'
                },
            'chain.pem': {
                'live': le / 'live' / 'a.com' / 'chain.pem',
                'archive': le / 'archive' / 'a.com' / 'chain1.pem',
                'dane': al / 'a.com' / 'chain.pem',
                'renew': le / 'archive' / 'a.com' / 'chain2.pem'
                },
            'fullchain.pem': {
                'live': le / 'live' / 'a.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'a.com' / 'fullchain1.pem',
                'dane': al / 'a.com' / 'fullchain.pem',
                'renew': le / 'archive' / 'a.com' / 'fullchain2.pem'
                },
            'privkey.pem': {
                'live': le / 'live' / 'a.com' / 'privkey.pem',
                'archive': le / 'archive' / 'a.com' / 'privkey1.pem',
                'dane': al / 'a.com' / 'privkey.pem',
                'renew': le / 'archive' / 'a.com' / 'privkey2.pem'
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al,
            san = False,
            ddd = al / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'b.com',
            ad = le / 'archive',
            add = le / 'archive' / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'b.com' / 'cert.pem',
                'archive': le / 'archive' / 'b.com' / 'cert1.pem',
                'dane': al / 'b.com' / 'cert.pem',
                'renew': le / 'archive' / 'b.com' / 'cert2.pem'
                },
            'chain.pem': {
                'live': le / 'live' / 'b.com' / 'chain.pem',
                'archive': le / 'archive' / 'b.com' / 'chain1.pem',
                'dane': al / 'b.com' / 'chain.pem',
                'renew': le / 'archive' / 'b.com' / 'chain2.pem'
                },
            'fullchain.pem': {
                'live': le / 'live' / 'b.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'b.com' / 'fullchain1.pem',
                'dane': al / 'b.com' / 'fullchain.pem',
                'renew': le / 'archive' / 'b.com' / 'fullchain2.pem'
                },
            'privkey.pem': {
                'live': le / 'live' / 'b.com' / 'privkey.pem',
                'archive': le / 'archive' / 'b.com' / 'privkey1.pem',
                'dane': al / 'b.com' / 'privkey.pem',
                'renew': le / 'archive' / 'b.com' / 'privkey2.pem'
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al,
            san = False,
            ddd = al / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'c.com',
            ad = le / 'archive',
            add = le / 'archive' / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'c.com' / 'cert.pem',
                'archive': le / 'archive' / 'c.com' / 'cert1.pem',
                'dane': al / 'c.com' / 'cert.pem',
                'renew': le / 'archive' / 'c.com' / 'cert2.pem'
                },
            'chain.pem': {
                'live': le / 'live' / 'c.com' / 'chain.pem',
                'archive': le / 'archive' / 'c.com' / 'chain1.pem',
                'dane': al / 'c.com' / 'chain.pem',
                'renew': le / 'archive' / 'c.com' / 'chain2.pem'
                },
            'fullchain.pem': {
                'live': le / 'live' / 'c.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'c.com' / 'fullchain1.pem',
                'dane': al / 'c.com' / 'fullchain.pem',
                'renew': le / 'archive' / 'c.com' / 'fullchain2.pem'
                },
            'privkey.pem': {
                'live': le / 'live' / 'c.com' / 'privkey.pem',
                'archive': le / 'archive' / 'c.com' / 'privkey1.pem',
                'dane': al / 'c.com' / 'privkey.pem',
                'renew': le / 'archive' / 'c.com' / 'privkey2.pem'
                }
            })
    assert s.targets['c.com']['tainted'] == False

    setup.check_record(s, 'a.com', '200', '25', 'tcp', rdomain='a.com',
                        data=setup.get_data('a.com', 2, '200'),
                        published=True, is_up=True)
    setup.check_record(s, 'a.com', '201', '25', 'tcp', rdomain='a.com',
                        data=setup.get_data('a.com', 2, '201'),
                        published=True)
    setup.check_record(s, 'a.com', '202', '25', 'tcp', rdomain='a.com',
                        data=setup.get_data('a.com', 2, '202'),
                        published=True)
    setup.check_record(s, 'a.com', '301', '25', 'tcp', rdomain='a.com',
                        prev_data=setup.get_data('a.com', 1, '301'),
                        data=setup.get_data('a.com', 2, '301'),
                        published=True, is_up=True)
    setup.check_record(s, 'a.com', '301', '2525', 'tcp', rdomain='a.com',
                        prev_data=setup.get_data('a.com', 1, '301'),
                        data=setup.get_data('a.com', 2, '301'),
                        published=True)
    setup.check_record(s, 'a.com', '301', '25', 'tcp', rdomain='a.a.com',
                        prev_data=setup.get_data('a.com', 1, '301'),
                        data=setup.get_data('a.com', 2, '301'),
                        published=True)

    setup.check_record(s, 'b.com', '211', '443', 'tcp', rdomain='b.com',
                        data=setup.get_data('b.com', 2, '211'),
                        published=True, is_up=True)
    setup.check_record(s, 'b.com', '311', '1234', 'abcp', rdomain='b.b.com',
                        prev_data=setup.get_data('b.com', 1, '311'),
                        data=setup.get_data('b.com', 2, '311'),
                        published=True)
    setup.check_record(s, 'b.com', '312', '5678', 'xyz', rdomain='b1.b.com',
                        prev_data=setup.get_data('b.com', 1, '312'),
                        data=setup.get_data('b.com', 2, '312'),
                        published=True)

    setup.check_record(s, 'c.com', '300', '1000', 'udp', rdomain='c.com',
                        prev_data=setup.get_data('c.com', 1, '300'),
                        data=setup.get_data('c.com', 2, '300'),
                        published=True, is_up=True)
    setup.check_record(s, 'c.com', '301', '1001', 'sctp', rdomain='c1.c.com',
                        prev_data=setup.get_data('c.com', 1, '301'),
                        data=setup.get_data('c.com', 2, '301'),
                        published=True, is_up=True)
    setup.check_record(s, 'c.com', '302', '1002', 'tcp', rdomain='c2.c.com',
                        prev_data=setup.get_data('c.com', 1, '302'),
                        data=setup.get_data('c.com', 2, '302'),
                        published=True, is_up=True)

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')


    setup.exists_and_is_file( al / 'a.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'cert.pem') )
                == '../../le/archive/a.com/cert1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'chain.pem') )
                == '../../le/archive/a.com/chain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'fullchain.pem') )
                == '../../le/archive/a.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'privkey.pem') )
                == '../../le/archive/a.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'b.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'cert.pem') )
                == '../../le/archive/b.com/cert1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'chain.pem') )
                == '../../le/archive/b.com/chain1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'fullchain.pem') )
                == '../../le/archive/b.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'privkey.pem') )
                == '../../le/archive/b.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'c.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'cert.pem') )
                == '../../le/live/c.com/cert.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'chain.pem') )
                == '../../le/live/c.com/chain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'fullchain.pem') )
                == '../../le/live/c.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'privkey.pem') )
                == '../../le/live/c.com/privkey.pem' )

    call_lines = setup.read_call_data()
    assert len(call_lines) == 12
    assert setup.is_in_call_data(call_lines, 'ALNITAK_LIVE_CERT_DATA') == 0
    assert setup.is_in_call_data(call_lines, 'ALNITAK_UPDATE') == 0
    assert setup.is_in_call_data(call_lines, 'ALNITAK_OPERATION=publish') == 12
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=a.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=25',
            'ALNITAK_PROTOCOL=tcp',
            'ALNITAK_DOMAIN=a.com',
            'ALNITAK_USAGE=2',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=0',
            'ALNITAK_PARAMS=2 0 0',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 2, '200')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=a.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=25',
            'ALNITAK_PROTOCOL=tcp',
            'ALNITAK_DOMAIN=a.com',
            'ALNITAK_USAGE=2',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=1',
            'ALNITAK_PARAMS=2 0 1',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 2, '201')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=a.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=25',
            'ALNITAK_PROTOCOL=tcp',
            'ALNITAK_DOMAIN=a.com',
            'ALNITAK_USAGE=2',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=2',
            'ALNITAK_PARAMS=2 0 2',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 2, '202')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=a.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=2525',
            'ALNITAK_PROTOCOL=tcp',
            'ALNITAK_DOMAIN=a.com',
            'ALNITAK_USAGE=3',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=1',
            'ALNITAK_PARAMS=3 0 1',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 2, '301')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=a.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=25',
            'ALNITAK_PROTOCOL=tcp',
            'ALNITAK_DOMAIN=a.a.com',
            'ALNITAK_USAGE=3',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=1',
            'ALNITAK_PARAMS=3 0 1',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 2, '301')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=a.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=25',
            'ALNITAK_PROTOCOL=tcp',
            'ALNITAK_DOMAIN=a.com',
            'ALNITAK_USAGE=3',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=1',
            'ALNITAK_PARAMS=3 0 1',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 2, '301')),
            ]) == 1

    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=b.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=443',
            'ALNITAK_PROTOCOL=tcp',
            'ALNITAK_DOMAIN=b.com',
            'ALNITAK_USAGE=2',
            'ALNITAK_SELECTOR=1',
            'ALNITAK_MATCHING_TYPE=1',
            'ALNITAK_PARAMS=2 1 1',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('b.com', 2, '211')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=b.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=1234',
            'ALNITAK_PROTOCOL=abcp',
            'ALNITAK_DOMAIN=b.b.com',
            'ALNITAK_USAGE=3',
            'ALNITAK_SELECTOR=1',
            'ALNITAK_MATCHING_TYPE=1',
            'ALNITAK_PARAMS=3 1 1',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('b.com', 2, '311')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=b.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=5678',
            'ALNITAK_PROTOCOL=xyz',
            'ALNITAK_DOMAIN=b1.b.com',
            'ALNITAK_USAGE=3',
            'ALNITAK_SELECTOR=1',
            'ALNITAK_MATCHING_TYPE=2',
            'ALNITAK_PARAMS=3 1 2',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('b.com', 2, '312')),
            ]) == 1

    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=c.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=1000',
            'ALNITAK_PROTOCOL=udp',
            'ALNITAK_DOMAIN=c.com',
            'ALNITAK_USAGE=3',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=0',
            'ALNITAK_PARAMS=3 0 0',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('c.com', 2, '300')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=c.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=1001',
            'ALNITAK_PROTOCOL=sctp',
            'ALNITAK_DOMAIN=c1.c.com',
            'ALNITAK_USAGE=3',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=1',
            'ALNITAK_PARAMS=3 0 1',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('c.com', 2, '301')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
            'ALNITAK_ZONE=c.com',
            'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
            'ALNITAK_PORT=1002',
            'ALNITAK_PROTOCOL=tcp',
            'ALNITAK_DOMAIN=c2.c.com',
            'ALNITAK_USAGE=3',
            'ALNITAK_SELECTOR=0',
            'ALNITAK_MATCHING_TYPE=2',
            'ALNITAK_PARAMS=3 0 2',
            'ALNITAK_CERT_DATA={}'.format(setup.get_data('c.com', 2, '302')),
            ]) == 1


    # DEPLOY CALL -- ttl passed. No errors.
    call_data = setup.reset_call_data()
    s.set_ttl('a.com', 0)
    s.set_ttl('b.com', 0)
    s.set_ttl('c.com', 0)
    s.renewed_domains = [] # unset renewed domains
    setup.set_update_api(s, 'a.com',
            [ '.alnitak_tests/bin/api', '201::1', '202::2',
              'delete:a.com:301:2525:tcp:a.com::1',
              'delete:a.com:301:25:tcp:a.a.com::2' ])
    setup.set_update_api(s, 'b.com',
            [ '.alnitak_tests/bin/api', 'delete::0'  ])
    setup.set_update_api(s, 'c.com',
            [ '.alnitak_tests/bin/api', 'delete::2' ])
    mode.deploy(s)

    # check state is correct
    assert s.renewed_domains == []
    assert len(s.handler.errors) == 2
    assert int(s.handler.errors[0]) == 3134
    assert int(s.handler.errors[1]) == 3134
    setup.str_in_list("'2 0 2' (_25._tcp.a.com)", s.handler.errors)
    setup.str_in_list("'3 0 1' (_25._tcp.a.a.com)", s.handler.errors)
    assert s.handler.warnings == []
    assert s.call == 'deploy'

    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    assert s.targets['a.com']['progress'] == 'deployed'
    assert s.targets['b.com']['progress'] == 'unprepared'
    assert s.targets['c.com']['progress'] == 'unprepared'

    assert s.targets['a.com']['prepared'] == True
    assert s.targets['b.com']['prepared'] == True
    assert s.targets['c.com']['prepared'] == True

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'a.com',
            ad = le / 'archive',
            add = le / 'archive' / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'a.com' / 'cert.pem',
                'archive': le / 'archive' / 'a.com' / 'cert1.pem',
                'dane': al / 'a.com' / 'cert.pem',
                'renew': le / 'archive' / 'a.com' / 'cert2.pem'
                },
            'chain.pem': {
                'live': le / 'live' / 'a.com' / 'chain.pem',
                'archive': le / 'archive' / 'a.com' / 'chain1.pem',
                'dane': al / 'a.com' / 'chain.pem',
                'renew': le / 'archive' / 'a.com' / 'chain2.pem'
                },
            'fullchain.pem': {
                'live': le / 'live' / 'a.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'a.com' / 'fullchain1.pem',
                'dane': al / 'a.com' / 'fullchain.pem',
                'renew': le / 'archive' / 'a.com' / 'fullchain2.pem'
                },
            'privkey.pem': {
                'live': le / 'live' / 'a.com' / 'privkey.pem',
                'archive': le / 'archive' / 'a.com' / 'privkey1.pem',
                'dane': al / 'a.com' / 'privkey.pem',
                'renew': le / 'archive' / 'a.com' / 'privkey2.pem'
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al,
            san = False,
            ddd = al / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'b.com',
            ad = le / 'archive',
            add = le / 'archive' / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'b.com' / 'cert.pem',
                'archive': le / 'archive' / 'b.com' / 'cert1.pem',
                'dane': al / 'b.com' / 'cert.pem',
                'renew': le / 'archive' / 'b.com' / 'cert2.pem'
                },
            'chain.pem': {
                'live': le / 'live' / 'b.com' / 'chain.pem',
                'archive': le / 'archive' / 'b.com' / 'chain1.pem',
                'dane': al / 'b.com' / 'chain.pem',
                'renew': le / 'archive' / 'b.com' / 'chain2.pem'
                },
            'fullchain.pem': {
                'live': le / 'live' / 'b.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'b.com' / 'fullchain1.pem',
                'dane': al / 'b.com' / 'fullchain.pem',
                'renew': le / 'archive' / 'b.com' / 'fullchain2.pem'
                },
            'privkey.pem': {
                'live': le / 'live' / 'b.com' / 'privkey.pem',
                'archive': le / 'archive' / 'b.com' / 'privkey1.pem',
                'dane': al / 'b.com' / 'privkey.pem',
                'renew': le / 'archive' / 'b.com' / 'privkey2.pem'
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al,
            san = False,
            ddd = al / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = le / 'live' / 'c.com',
            ad = le / 'archive',
            add = le / 'archive' / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': le / 'live' / 'c.com' / 'cert.pem',
                'archive': le / 'archive' / 'c.com' / 'cert1.pem',
                'dane': al / 'c.com' / 'cert.pem',
                'renew': le / 'archive' / 'c.com' / 'cert2.pem'
                },
            'chain.pem': {
                'live': le / 'live' / 'c.com' / 'chain.pem',
                'archive': le / 'archive' / 'c.com' / 'chain1.pem',
                'dane': al / 'c.com' / 'chain.pem',
                'renew': le / 'archive' / 'c.com' / 'chain2.pem'
                },
            'fullchain.pem': {
                'live': le / 'live' / 'c.com' / 'fullchain.pem',
                'archive': le / 'archive' / 'c.com' / 'fullchain1.pem',
                'dane': al / 'c.com' / 'fullchain.pem',
                'renew': le / 'archive' / 'c.com' / 'fullchain2.pem'
                },
            'privkey.pem': {
                'live': le / 'live' / 'c.com' / 'privkey.pem',
                'archive': le / 'archive' / 'c.com' / 'privkey1.pem',
                'dane': al / 'c.com' / 'privkey.pem',
                'renew': le / 'archive' / 'c.com' / 'privkey2.pem'
                }
            })
    assert s.targets['c.com']['tainted'] == False

    setup.check_record(s, 'a.com', '200', '25', 'tcp', rdomain='a.com',
                        data=setup.get_data('a.com', 2, '200'),
                        published=True, is_up=True)
    # 201 delete fails, but do not set a delete since prev matches new
    setup.check_record(s, 'a.com', '201', '25', 'tcp', rdomain='a.com',
                        data=setup.get_data('a.com', 2, '201'),
                        published=True)
    setup.check_record(s, 'a.com', '202', '25', 'tcp', rdomain='a.com',
                        data=setup.get_data('a.com', 2, '202'),
                        published=True, is_up=True)
    setup.check_record(s, 'a.com', '301', '25', 'tcp', rdomain='a.com',
                        prev_data=setup.get_data('a.com', 1, '301'),
                        data=setup.get_data('a.com', 2, '301'),
                        published=True, is_up=True)
    setup.check_record(s, 'a.com', '301', '2525', 'tcp', rdomain='a.com',
                        prev_data=setup.get_data('a.com', 1, '301'),
                        data=setup.get_data('a.com', 2, '301'),
                        published=True)
    setup.check_record(s, 'a.com', '301', '25', 'tcp', rdomain='a.a.com',
                        delete_data=setup.get_data('a.com', 1, '301'),
                        data=setup.get_data('a.com', 2, '301'),
                        published=True, is_up=True)

    setup.check_record(s, 'b.com', '211', '443', 'tcp', rdomain='b.com',
                        data=setup.get_data('b.com', 2, '211'),
                        published=True, is_up=True)
    setup.check_record(s, 'b.com', '311', '1234', 'abcp', rdomain='b.b.com',
                        prev_data=setup.get_data('b.com', 1, '311'),
                        data=setup.get_data('b.com', 2, '311'),
                        published=True, is_up=True)
    setup.check_record(s, 'b.com', '312', '5678', 'xyz', rdomain='b1.b.com',
                        prev_data=setup.get_data('b.com', 1, '312'),
                        data=setup.get_data('b.com', 2, '312'),
                        published=True, is_up=True)

    setup.check_record(s, 'c.com', '300', '1000', 'udp', rdomain='c.com',
                        prev_data=setup.get_data('c.com', 1, '300'),
                        data=setup.get_data('c.com', 2, '300'),
                        published=True, is_up=True)
    setup.check_record(s, 'c.com', '301', '1001', 'sctp', rdomain='c1.c.com',
                        prev_data=setup.get_data('c.com', 1, '301'),
                        data=setup.get_data('c.com', 2, '301'),
                        published=True, is_up=True)
    setup.check_record(s, 'c.com', '302', '1002', 'tcp', rdomain='c2.c.com',
                        prev_data=setup.get_data('c.com', 1, '302'),
                        data=setup.get_data('c.com', 2, '302'),
                        published=True, is_up=True)

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')


    setup.exists_and_is_file( al / 'a.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'cert.pem') )
                == '../../le/archive/a.com/cert1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'chain.pem') )
                == '../../le/archive/a.com/chain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'fullchain.pem') )
                == '../../le/archive/a.com/fullchain1.pem' )
    setup.exists_and_is_file( al / 'a.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'a.com' / 'privkey.pem') )
                == '../../le/archive/a.com/privkey1.pem' )

    setup.exists_and_is_file( al / 'b.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'cert.pem') )
                == '../../le/live/b.com/cert.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'chain.pem') )
                == '../../le/live/b.com/chain.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'fullchain.pem') )
                == '../../le/live/b.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'b.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'b.com' / 'privkey.pem') )
                == '../../le/live/b.com/privkey.pem' )

    setup.exists_and_is_file( al / 'c.com' / 'cert.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'cert.pem') )
                == '../../le/live/c.com/cert.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'chain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'chain.pem') )
                == '../../le/live/c.com/chain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'fullchain.pem') )
                == '../../le/live/c.com/fullchain.pem' )
    setup.exists_and_is_file( al / 'c.com' / 'privkey.pem', symlink=True)
    assert ( os.readlink( str(al / 'c.com' / 'privkey.pem') )
                == '../../le/live/c.com/privkey.pem' )

    call_lines = setup.read_call_data()
    assert len(call_lines) == 6
    assert setup.is_in_call_data(call_lines, 'ALNITAK_LIVE_CERT_DATA') == 0
    assert setup.is_in_call_data(call_lines, 'ALNITAK_OPERATION=delete') == 6
    assert setup.is_in_call_data(call_lines, [
                'ALNITAK_ZONE=a.com',
                'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
                'ALNITAK_PORT=25',
                'ALNITAK_PROTOCOL=tcp',
                'ALNITAK_DOMAIN=a.com',
                'ALNITAK_USAGE=2',
                'ALNITAK_SELECTOR=0',
                'ALNITAK_MATCHING_TYPE=1',
                'ALNITAK_PARAMS=2 0 1',
                'ALNITAK_LIVE_CERT_DATA={}'.format(setup.get_data('a.com', 2, '201')),
            ]) == 1
    # ALNITAK_CERT_DATA does not appear in 2xx read_delete record
    assert setup.is_in_call_data(call_lines, [
                'ALNITAK_ZONE=a.com',
                'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
                'ALNITAK_PORT=25',
                'ALNITAK_PROTOCOL=tcp',
                'ALNITAK_DOMAIN=a.com',
                'ALNITAK_USAGE=2',
                'ALNITAK_SELECTOR=0',
                'ALNITAK_MATCHING_TYPE=1',
                'ALNITAK_PARAMS=2 0 1',
                'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 1, '201')),
                'ALNITAK_LIVE_CERT_DATA={}'.format(setup.get_data('a.com', 2, '201')),
            ]) == 0

    assert setup.is_in_call_data(call_lines, [
                'ALNITAK_ZONE=a.com',
                'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
                'ALNITAK_PORT=25',
                'ALNITAK_PROTOCOL=tcp',
                'ALNITAK_DOMAIN=a.com',
                'ALNITAK_USAGE=2',
                'ALNITAK_SELECTOR=0',
                'ALNITAK_MATCHING_TYPE=2',
                'ALNITAK_PARAMS=2 0 2',
                'ALNITAK_LIVE_CERT_DATA={}'.format(setup.get_data('a.com', 2, '202')),
            ]) == 1
    # ALNITAK_CERT_DATA does not appear in 2xx read_delete record
    assert setup.is_in_call_data(call_lines, [
                'ALNITAK_ZONE=a.com',
                'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
                'ALNITAK_PORT=25',
                'ALNITAK_PROTOCOL=tcp',
                'ALNITAK_DOMAIN=a.com',
                'ALNITAK_USAGE=2',
                'ALNITAK_SELECTOR=0',
                'ALNITAK_MATCHING_TYPE=2',
                'ALNITAK_PARAMS=2 0 2',
                'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 1, '202')),
                'ALNITAK_LIVE_CERT_DATA={}'.format(setup.get_data('a.com', 2, '202')),
            ]) == 0

    assert setup.is_in_call_data(call_lines, [
                'ALNITAK_ZONE=a.com',
                'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
                'ALNITAK_PORT=2525',
                'ALNITAK_PROTOCOL=tcp',
                'ALNITAK_DOMAIN=a.com',
                'ALNITAK_USAGE=3',
                'ALNITAK_SELECTOR=0',
                'ALNITAK_MATCHING_TYPE=1',
                'ALNITAK_PARAMS=3 0 1',
                'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 1, '301')),
                'ALNITAK_LIVE_CERT_DATA={}'.format(setup.get_data('a.com', 2, '301')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
                'ALNITAK_ZONE=a.com',
                'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
                'ALNITAK_PORT=25',
                'ALNITAK_PROTOCOL=tcp',
                'ALNITAK_DOMAIN=a.a.com',
                'ALNITAK_USAGE=3',
                'ALNITAK_SELECTOR=0',
                'ALNITAK_MATCHING_TYPE=1',
                'ALNITAK_PARAMS=3 0 1',
                'ALNITAK_CERT_DATA={}'.format(setup.get_data('a.com', 1, '301')),
                'ALNITAK_LIVE_CERT_DATA={}'.format(setup.get_data('a.com', 2, '301')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
                'ALNITAK_ZONE=b.com',
                'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
                'ALNITAK_PORT=1234',
                'ALNITAK_PROTOCOL=abcp',
                'ALNITAK_DOMAIN=b.b.com',
                'ALNITAK_USAGE=3',
                'ALNITAK_SELECTOR=1',
                'ALNITAK_MATCHING_TYPE=1',
                'ALNITAK_PARAMS=3 1 1',
                'ALNITAK_CERT_DATA={}'.format(setup.get_data('b.com', 1, '311')),
                'ALNITAK_LIVE_CERT_DATA={}'.format(setup.get_data('b.com', 2, '311')),
            ]) == 1
    assert setup.is_in_call_data(call_lines, [
                'ALNITAK_ZONE=b.com',
                'ALNITAK_LETSENCRYPT_DIR=.alnitak_tests/etc/le',
                'ALNITAK_PORT=5678',
                'ALNITAK_PROTOCOL=xyz',
                'ALNITAK_DOMAIN=b1.b.com',
                'ALNITAK_USAGE=3',
                'ALNITAK_SELECTOR=1',
                'ALNITAK_MATCHING_TYPE=2',
                'ALNITAK_PARAMS=3 1 2',
                'ALNITAK_CERT_DATA={}'.format(setup.get_data('b.com', 1, '312')),
                'ALNITAK_LIVE_CERT_DATA={}'.format(setup.get_data('b.com', 2, '312')),
            ]) == 1

