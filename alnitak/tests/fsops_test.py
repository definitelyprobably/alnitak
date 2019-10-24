
import os
import shutil
from pathlib import Path

from alnitak.tests import setup
from alnitak import state
from alnitak import fsops

def test_relative_to():
    assert fsops.relative_to('/a/b/c/d/from', '/a/b/e/f/to') == '../../e/f/to'
    assert fsops.relative_to('a/b/c/d/from', 'a/b/e/f/to') == '../../e/f/to'
    assert fsops.relative_to('/a/b/from', '/a/b/c/d/to') == 'c/d/to'
    assert fsops.relative_to('a/b/from', 'a/b/c/d/to') == 'c/d/to'
    assert fsops.relative_to('/a/b/c/d/from', '/a/b/to') == '../../to'
    assert fsops.relative_to('a/b/c/d/from', 'a/b/to') == '../../to'
    assert fsops.relative_to('/a/b/c/from', '/a/b/c/to') == 'to'
    assert fsops.relative_to('a/b/c/from', 'a/b/c/to') == 'to'
    assert fsops.relative_to('/a/b/c/from', '/A/b/c/to') == '../../../A/b/c/to'
    assert fsops.relative_to('/a/b/c/from', '/a/B/c/to') == '../../B/c/to'
    assert fsops.relative_to('a/b/c/from', 'A/b/c/to') == '../../../A/b/c/to'
    assert fsops.relative_to('a/b/c/from', 'a/B/c/to') == '../../B/c/to'
    assert fsops.relative_to('from', 'a/b/to') == 'a/b/to'
    assert fsops.relative_to('from', '/a/b/to') == '/a/b/to'



def test_init_dane_directory_1():
    '''
    Expect DD to be created and populated with links to live certs.
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

    s.set_call_init()

    fsops.init_dane_directory(s)

    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'init'

    # check state is correct
    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = (le / 'live') / 'a.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'a.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'a.com') / 'cert1.pem',
                'dane': (al / 'a.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'a.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'a.com') / 'chain1.pem',
                'dane': (al / 'a.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'a.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'a.com') / 'fullchain1.pem',
                'dane': (al / 'a.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'a.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'a.com') / 'privkey1.pem',
                'dane': (al / 'a.com') / 'privkey.pem',
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
            ldd = (le / 'live') / 'b.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'b.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'b.com') / 'cert1.pem',
                'dane': (al / 'b.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'b.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'b.com') / 'chain1.pem',
                'dane': (al / 'b.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'b.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'b.com') / 'fullchain1.pem',
                'dane': (al / 'b.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'b.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'b.com') / 'privkey1.pem',
                'dane': (al / 'b.com') / 'privkey.pem',
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
            ldd = (le / 'live') / 'c.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'c.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'c.com') / 'cert1.pem',
                'dane': (al / 'c.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'c.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'c.com') / 'chain1.pem',
                'dane': (al / 'c.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'c.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'c.com') / 'fullchain1.pem',
                'dane': (al / 'c.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'c.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'c.com') / 'privkey1.pem',
                'dane': (al / 'c.com') / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False

    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')

    setup.exists_and_is_file( (al / 'a.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al / 'a.com') / 'cert.pem') )
                == '../../le/live/a.com/cert.pem' )
    setup.exists_and_is_file( (al / 'a.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al / 'a.com') / 'chain.pem') )
                == '../../le/live/a.com/chain.pem' )
    setup.exists_and_is_file( (al / 'a.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al / 'a.com') / 'fullchain.pem') )
                == '../../le/live/a.com/fullchain.pem' )
    setup.exists_and_is_file( (al / 'a.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al / 'a.com') / 'privkey.pem') )
                == '../../le/live/a.com/privkey.pem' )

    setup.exists_and_is_file( (al / 'b.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al / 'b.com') / 'cert.pem') )
                == '../../le/live/b.com/cert.pem' )
    setup.exists_and_is_file( (al / 'b.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al / 'b.com') / 'chain.pem') )
                == '../../le/live/b.com/chain.pem' )
    setup.exists_and_is_file( (al / 'b.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al / 'b.com') / 'fullchain.pem') )
                == '../../le/live/b.com/fullchain.pem' )
    setup.exists_and_is_file( (al / 'b.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al / 'b.com') / 'privkey.pem') )
                == '../../le/live/b.com/privkey.pem' )

    setup.exists_and_is_file( (al / 'c.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al / 'c.com') / 'cert.pem') )
                == '../../le/live/c.com/cert.pem' )
    setup.exists_and_is_file( (al / 'c.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al / 'c.com') / 'chain.pem') )
                == '../../le/live/c.com/chain.pem' )
    setup.exists_and_is_file( (al / 'c.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al / 'c.com') / 'fullchain.pem') )
                == '../../le/live/c.com/fullchain.pem' )
    setup.exists_and_is_file( (al / 'c.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al / 'c.com') / 'privkey.pem') )
                == '../../le/live/c.com/privkey.pem' )



def test_init_dane_directory_2():
    '''
    Expect DD to be created and populated with links to archive certs.
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

    fsops.init_dane_directory(s)

    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == None

    # check state is correct
    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    setup.check_state_dirs(s, 'a.com',
            dd = al,
            san = False,
            ddd = al / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = (le / 'live') / 'a.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'a.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'a.com') / 'cert1.pem',
                'dane': (al / 'a.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'a.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'a.com') / 'chain1.pem',
                'dane': (al / 'a.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'a.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'a.com') / 'fullchain1.pem',
                'dane': (al / 'a.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'a.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'a.com') / 'privkey1.pem',
                'dane': (al / 'a.com') / 'privkey.pem',
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
            ldd = (le / 'live') / 'b.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'b.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'b.com') / 'cert1.pem',
                'dane': (al / 'b.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'b.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'b.com') / 'chain1.pem',
                'dane': (al / 'b.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'b.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'b.com') / 'fullchain1.pem',
                'dane': (al / 'b.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'b.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'b.com') / 'privkey1.pem',
                'dane': (al / 'b.com') / 'privkey.pem',
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
            ldd = (le / 'live') / 'c.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'c.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'c.com') / 'cert1.pem',
                'dane': (al / 'c.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'c.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'c.com') / 'chain1.pem',
                'dane': (al / 'c.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'c.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'c.com') / 'fullchain1.pem',
                'dane': (al / 'c.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'c.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'c.com') / 'privkey1.pem',
                'dane': (al / 'c.com') / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False


    # check fs is correct
    setup.exists_and_is_dir(al)
    if os.getuid() == 0:
        assert al.stat().st_uid == 0
        assert al.stat().st_gid == 0
    assert al.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al / 'a.com')
    setup.exists_and_is_dir(al / 'b.com')
    setup.exists_and_is_dir(al / 'c.com')

    setup.exists_and_is_file( (al / 'a.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al / 'a.com') / 'cert.pem') )
                == '../../le/archive/a.com/cert1.pem' )
    setup.exists_and_is_file( (al / 'a.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al / 'a.com') / 'chain.pem') )
                == '../../le/archive/a.com/chain1.pem' )
    setup.exists_and_is_file( (al / 'a.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al / 'a.com') / 'fullchain.pem') )
                == '../../le/archive/a.com/fullchain1.pem' )
    setup.exists_and_is_file( (al / 'a.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al / 'a.com') / 'privkey.pem') )
                == '../../le/archive/a.com/privkey1.pem' )

    setup.exists_and_is_file( (al / 'b.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al / 'b.com') / 'cert.pem') )
                == '../../le/archive/b.com/cert1.pem' )
    setup.exists_and_is_file( (al / 'b.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al / 'b.com') / 'chain.pem') )
                == '../../le/archive/b.com/chain1.pem' )
    setup.exists_and_is_file( (al / 'b.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al / 'b.com') / 'fullchain.pem') )
                == '../../le/archive/b.com/fullchain1.pem' )
    setup.exists_and_is_file( (al / 'b.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al / 'b.com') / 'privkey.pem') )
                == '../../le/archive/b.com/privkey1.pem' )

    setup.exists_and_is_file( (al / 'c.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al / 'c.com') / 'cert.pem') )
                == '../../le/archive/c.com/cert1.pem' )
    setup.exists_and_is_file( (al / 'c.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al / 'c.com') / 'chain.pem') )
                == '../../le/archive/c.com/chain1.pem' )
    setup.exists_and_is_file( (al / 'c.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al / 'c.com') / 'fullchain.pem') )
                == '../../le/archive/c.com/fullchain1.pem' )
    setup.exists_and_is_file( (al / 'c.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al / 'c.com') / 'privkey.pem') )
                == '../../le/archive/c.com/privkey1.pem' )



def test_init_dane_directory_3():
    '''
    Test multiple DD creation success and then sanitizing.
    Then run again to test various failures.
    '''
    # create testing directory
    le = setup.create_testing_base_dir()

    # define alnitak directory
    al_parent = le.parent / 'al'
    al_a = (al_parent / 'a') / 'al_a.com'
    al_b = (al_parent / 'b') / 'al_b.com'
    al_c = (al_parent / 'c') / 'al_c.com'

    # remove alnitak directories, if present
    if al_parent.exists():
        shutil.rmtree(str(al_parent))


    # create state object
    s = state.State()

    # skip the chmod code
    if os.getuid() != 0:
        s.testing_mode = True

    # use the setup handler to capture errors/warnings
    s.handler = setup.Handler()

    s.create_target('a.com')
    s.set_letsencrypt_directory('a.com', le)
    s.set_dane_directory('a.com', al_a)

    s.create_target('b.com')
    s.set_letsencrypt_directory('b.com', le)
    s.set_dane_directory('b.com', al_b)

    s.create_target('c.com')
    s.set_letsencrypt_directory('c.com', le)
    s.set_dane_directory('c.com', al_c)

    s.set_call_init()

    fsops.init_dane_directory(s)

    assert s.renewed_domains == []
    assert s.handler.errors == []
    assert s.handler.warnings == []
    assert s.call == 'init'

    # check state is correct
    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    setup.check_state_dirs(s, 'a.com',
            dd = al_a,
            san = False,
            ddd = al_a / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = (le / 'live') / 'a.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'a.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'a.com') / 'cert1.pem',
                'dane': (al_a / 'a.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'a.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'a.com') / 'chain1.pem',
                'dane': (al_a / 'a.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'a.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'a.com') / 'fullchain1.pem',
                'dane': (al_a / 'a.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'a.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'a.com') / 'privkey1.pem',
                'dane': (al_a / 'a.com') / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al_b,
            san = False,
            ddd = al_b / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = (le / 'live') / 'b.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'b.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'b.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'b.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'b.com') / 'cert1.pem',
                'dane': (al_b / 'b.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'b.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'b.com') / 'chain1.pem',
                'dane': (al_b / 'b.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'b.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'b.com') / 'fullchain1.pem',
                'dane': (al_b / 'b.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'b.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'b.com') / 'privkey1.pem',
                'dane': (al_b / 'b.com') / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['b.com']['tainted'] == False

    setup.check_state_dirs(s, 'c.com',
            dd = al_c,
            san = False,
            ddd = al_c / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = (le / 'live') / 'c.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'c.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'c.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'c.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'c.com') / 'cert1.pem',
                'dane': (al_c / 'c.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'c.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'c.com') / 'chain1.pem',
                'dane': (al_c / 'c.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'c.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'c.com') / 'fullchain1.pem',
                'dane': (al_c / 'c.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'c.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'c.com') / 'privkey1.pem',
                'dane': (al_c / 'c.com') / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['c.com']['tainted'] == False

    # check fs is correct
    setup.exists_and_is_dir(al_a)
    if os.getuid() == 0:
        assert al_a.stat().st_uid == 0
        assert al_a.stat().st_gid == 0
    assert al_a.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al_b)
    if os.getuid() == 0:
        assert al_b.stat().st_uid == 0
        assert al_b.stat().st_gid == 0
    assert al_b.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al_c)
    if os.getuid() == 0:
        assert al_c.stat().st_uid == 0
        assert al_c.stat().st_gid == 0
    assert al_c.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_dir(al_a / 'a.com')
    setup.exists_and_is_dir(al_b / 'b.com')
    setup.exists_and_is_dir(al_c / 'c.com')

    setup.exists_and_is_file( (al_a / 'a.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al_a / 'a.com') / 'cert.pem') )
                == '../../../../le/live/a.com/cert.pem' )
    setup.exists_and_is_file( (al_a / 'a.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al_a / 'a.com') / 'chain.pem') )
                == '../../../../le/live/a.com/chain.pem' )
    setup.exists_and_is_file( (al_a / 'a.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al_a / 'a.com') / 'fullchain.pem') )
                == '../../../../le/live/a.com/fullchain.pem' )
    setup.exists_and_is_file( (al_a / 'a.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al_a / 'a.com') / 'privkey.pem') )
                == '../../../../le/live/a.com/privkey.pem' )

    setup.exists_and_is_file( (al_b / 'b.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al_b / 'b.com') / 'cert.pem') )
                == '../../../../le/live/b.com/cert.pem' )
    setup.exists_and_is_file( (al_b / 'b.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al_b / 'b.com') / 'chain.pem') )
                == '../../../../le/live/b.com/chain.pem' )
    setup.exists_and_is_file( (al_b / 'b.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al_b / 'b.com') / 'fullchain.pem') )
                == '../../../../le/live/b.com/fullchain.pem' )
    setup.exists_and_is_file( (al_b / 'b.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al_b / 'b.com') / 'privkey.pem') )
                == '../../../../le/live/b.com/privkey.pem' )

    setup.exists_and_is_file( (al_c / 'c.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al_c / 'c.com') / 'cert.pem') )
                == '../../../../le/live/c.com/cert.pem' )
    setup.exists_and_is_file( (al_c / 'c.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al_c / 'c.com') / 'chain.pem') )
                == '../../../../le/live/c.com/chain.pem' )
    setup.exists_and_is_file( (al_c / 'c.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al_c / 'c.com') / 'fullchain.pem') )
                == '../../../../le/live/c.com/fullchain.pem' )
    setup.exists_and_is_file( (al_c / 'c.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al_c / 'c.com') / 'privkey.pem') )
                == '../../../../le/live/c.com/privkey.pem' )

    # at this point, the DDs have been created (and tested). Now, let's
    # change the change the permissions and sanitize to check if sanitizing
    # works. We can also simulate some failures.

    # recreate state object
    s = state.State()

    # skip the chmod code
    if os.getuid() != 0:
        s.testing_mode = True

    # use the setup handler to capture errors/warnings
    s.handler = setup.Handler()

    s.create_target('a.com')
    s.set_letsencrypt_directory('a.com', le)
    s.set_dane_directory('a.com', al_a)

    s.create_target('b.com')
    s.set_letsencrypt_directory('b.com', le)
    s.set_dane_directory('b.com', al_b)

    s.create_target('c.com')
    s.set_letsencrypt_directory('c.com', le)
    s.set_dane_directory('c.com', al_c)

    s.set_call_init()

    # set sanitize
    s.set_sanitize('a.com')
    s.set_sanitize('b.com')
    s.set_sanitize('c.com')


    # a.com: mess with DD permissions
    os.chmod(str(al_a), 0o755)
    if os.getuid() == 0:
        os.chown(str(al_a), 1000, 1000)

    # b.com: remove the DD and replace with a file
    if al_b.exists():
        shutil.rmtree(str(al_b))
    with open(str(al_b), 'w') as f:
        f.write('\n')

    # c.com: remove the DD and change parent directory permissions
    if al_c.exists():
        shutil.rmtree(str(al_c))
    os.chmod(str(al_c.parent), 0o000)


    fsops.init_dane_directory(s)

    s.debug_print()
    print(s.handler.errors)

    assert s.renewed_domains == []

    assert len(s.handler.errors) == 2
    # b.com failure
    assert 1000 in [ int(e) for e in s.handler.errors ]
    # c.com failure
    assert 1001 in [ int(e) for e in s.handler.errors ]

    assert s.handler.warnings == []
    assert s.call == 'init'

    # check state is correct
    setup.check_state_domain(s, ['a.com', 'b.com', 'c.com'])

    setup.check_state_dirs(s, 'a.com',
            dd = al_a,
            san = True,
            ddd = al_a / 'a.com',
            led = le,
            ld = le / 'live',
            ldd = (le / 'live') / 'a.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'a.com',
            ll = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'] )
    setup.check_state_certs(s, 'a.com',
            {
            'cert.pem': {
                'live': ((le / 'live') / 'a.com') / 'cert.pem',
                'archive': ((le / 'archive') / 'a.com') / 'cert1.pem',
                'dane': (al_a / 'a.com') / 'cert.pem',
                'renew': None
                },
            'chain.pem': {
                'live': ((le / 'live') / 'a.com') / 'chain.pem',
                'archive': ((le / 'archive') / 'a.com') / 'chain1.pem',
                'dane': (al_a / 'a.com') / 'chain.pem',
                'renew': None
                },
            'fullchain.pem': {
                'live': ((le / 'live') / 'a.com') / 'fullchain.pem',
                'archive': ((le / 'archive') / 'a.com') / 'fullchain1.pem',
                'dane': (al_a / 'a.com') / 'fullchain.pem',
                'renew': None
                },
            'privkey.pem': {
                'live': ((le / 'live') / 'a.com') / 'privkey.pem',
                'archive': ((le / 'archive') / 'a.com') / 'privkey1.pem',
                'dane': (al_a / 'a.com') / 'privkey.pem',
                'renew': None
                }
            })
    assert s.targets['a.com']['tainted'] == False

    setup.check_state_dirs(s, 'b.com',
            dd = al_b,
            san = True,
            ddd = al_b / 'b.com',
            led = le,
            ld = le / 'live',
            ldd = (le / 'live') / 'b.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'b.com',
            ll = [] )
    setup.check_state_certs(s, 'b.com', {})
    assert s.targets['b.com']['tainted'] == True

    setup.check_state_dirs(s, 'c.com',
            dd = al_c,
            san = True,
            ddd = al_c / 'c.com',
            led = le,
            ld = le / 'live',
            ldd = (le / 'live') / 'c.com',
            ad = le / 'archive',
            add = (le / 'archive') / 'c.com',
            ll = [] )
    setup.check_state_certs(s, 'c.com', {})
    assert s.targets['c.com']['tainted'] == True

    # check fs is correct
    setup.exists_and_is_dir(al_a)
    if os.getuid() == 0:
        assert al_a.stat().st_uid == 0
        assert al_a.stat().st_gid == 0
    assert al_a.stat().st_mode == 16832 # 0o40700

    setup.exists_and_is_file(al_b)

    setup.exists_and_is_dir(al_a / 'a.com')

    setup.exists_and_is_file( (al_a / 'a.com') / 'cert.pem', symlink=True)
    assert ( os.readlink( str((al_a / 'a.com') / 'cert.pem') )
                == '../../../../le/live/a.com/cert.pem' )
    setup.exists_and_is_file( (al_a / 'a.com') / 'chain.pem', symlink=True)
    assert ( os.readlink( str((al_a / 'a.com') / 'chain.pem') )
                == '../../../../le/live/a.com/chain.pem' )
    setup.exists_and_is_file( (al_a / 'a.com') / 'fullchain.pem', symlink=True)
    assert ( os.readlink( str((al_a / 'a.com') / 'fullchain.pem') )
                == '../../../../le/live/a.com/fullchain.pem' )
    setup.exists_and_is_file( (al_a / 'a.com') / 'privkey.pem', symlink=True)
    assert ( os.readlink( str((al_a / 'a.com') / 'privkey.pem') )
                == '../../../../le/live/a.com/privkey.pem' )


    # cleanup
    os.chmod(str(al_c.parent), 0o700)
    if al_parent.exists():
        shutil.rmtree(str(al_parent))


