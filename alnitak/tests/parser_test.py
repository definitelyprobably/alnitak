
from alnitak.tests import setup
from alnitak import prog
from alnitak import parser as Parser

from pathlib import Path
from subprocess import Popen, PIPE



s = setup.Init(keep=True)
prog = setup.create_state_obj(s)

a_flag = Parser.Flag(Parser.FlagType.bare, '-a', '--aflag')
b_flag = Parser.Flag(Parser.FlagType.bare, '-b', '--bflag')
c_flag = Parser.Flag(Parser.FlagType.bare, '-c', '--cflag')

x_flag = Parser.Flag(Parser.FlagType.option, '-x', '--xflag')
y_flag = Parser.Flag(Parser.FlagType.option, '-y', '--yflag')
z_flag = Parser.Flag(Parser.FlagType.option, '-z', '--zflag')

m_flag = Parser.Flag(Parser.FlagType.mandatory, '-m', '--mflag')
n_flag = Parser.Flag(Parser.FlagType.mandatory, '-n', '--nflag')
o_flag = Parser.Flag(Parser.FlagType.mandatory, '-o', '--oflag')

def icheck(prog, pos, name, input):
    if input == 'A':
        return 1
    if input == 'B':
        return 2
    if input == '1100':
        raise Parser.Error1100('pos1', 'arg1', 'ref1', 'max1')
    if input == '1200':
        raise Parser.Error1200('pos2', 'arg2', 'ref2')
    if input == '1210':
        raise Parser.Error1210('pos3', 'arg3', 'ref3', 'spec1')
    if input == '1211':
        raise Parser.Error1211('pos4', 'arg4', 'ref4', 'spec2')
    if input == '1212':
        raise Parser.Error1212('pos5', 'arg5', 'ref5', 'spec3')
    return 0


def test_parser1():
    p = Parser.Parser(prog)
    p.add_flag(a_flag, b_flag, c_flag, x_flag, y_flag, z_flag,
               m_flag, n_flag, o_flag)

    args = [ 'PROGRAM_NAME' ]

    retval = p.parse_args(args)
    assert not retval

    assert p.instances == []

    for f in [ 'a', 'b', 'c', 'x', 'y', 'z', 'm', 'n', 'o' ]:
        ret = p.has(f)
        assert ret == False

    assert p.errors == []
    assert p.inputs == []

def test_parser2():
    p = Parser.Parser(prog)
    p.add_flag(a_flag, b_flag, c_flag, x_flag, y_flag, z_flag,
               m_flag, n_flag, o_flag)

    args = [ 'PROGRAM_NAME',
             '-a', '-b',
             '-x', '-x', 'X1', '-xX2',
             '--yflag', '--yflag', 'Y1', '--yflag=Y2',
             '-m', 'M1', '-mM2', '--mflag', 'M3', '--mflag=M4' ]

    retval = p.parse_args(args)
    assert not retval

    assert p.errors == []
    assert p.inputs == []

    assert len(p.instances) == 12

    assert p.instances[0].flag_name == '-a'
    assert not p.instances[0].flag_input
    assert p.instances[0].pos == 1

    assert p.instances[1].flag_name == '-b'
    assert not p.instances[1].flag_input
    assert p.instances[1].pos == 2

    assert p.instances[2].flag_name == '-x'
    assert not p.instances[2].flag_input
    assert p.instances[2].pos == 3

    assert p.instances[3].flag_name == '-x'
    assert p.instances[3].flag_input == 'X1'
    assert p.instances[3].pos == 4

    assert p.instances[4].flag_name == '-x'
    assert p.instances[4].flag_input == 'X2'
    assert p.instances[4].pos == 6

    assert p.instances[5].flag_name == '--yflag'
    assert not p.instances[5].flag_input
    assert p.instances[5].pos == 7

    assert p.instances[6].flag_name == '--yflag'
    assert p.instances[6].flag_input == 'Y1'
    assert p.instances[6].pos == 8

    assert p.instances[7].flag_name == '--yflag'
    assert p.instances[7].flag_input == 'Y2'
    assert p.instances[7].pos == 10

    assert p.instances[8].flag_name == '-m'
    assert p.instances[8].flag_input == 'M1'
    assert p.instances[8].pos == 11

    assert p.instances[9].flag_name == '-m'
    assert p.instances[9].flag_input == 'M2'
    assert p.instances[9].pos == 13

    assert p.instances[10].flag_name == '--mflag'
    assert p.instances[10].flag_input == 'M3'
    assert p.instances[10].pos == 14

    assert p.instances[11].flag_name == '--mflag'
    assert p.instances[11].flag_input == 'M4'
    assert p.instances[11].pos == 16

    val = p.has('a')
    assert val == True

    val = p.has('b')
    assert val == True

    val = p.has('c')
    assert val == False

    val = p.has('x')
    assert val == 'X2'

    val = p.has('y')
    assert val == 'Y2'

    val = p.has('z')
    assert val == False

    val = p.has('m')
    assert val == 'M4'

    val = p.has('n')
    assert val == False

    val = p.has('o')
    assert val == False

def test_parser3():
    p = Parser.Parser(prog)
    p.add_flag(a_flag, b_flag, x_flag, y_flag, m_flag, n_flag)
    mode = Parser.Mode()
    mode.add_flag(c_flag, z_flag, o_flag)
    p.add_mode(mode)

    args = [ 'PROGRAM_NAME',
             '-a', '-b',
             '-x', '-x', 'X1', '-xX2',
             '--yflag', '--yflag', 'Y1', '--yflag=Y2',
             '-m', 'M1', '-mM2', '--mflag', 'M3', '--mflag=M4' ]

    retval = p.parse_args(args)
    assert not retval

    assert p.errors == []
    assert p.inputs == []

    assert len(p.instances) == 12

    assert p.instances[0].flag_name == '-a'
    assert not p.instances[0].flag_input
    assert p.instances[0].pos == 1

    assert p.instances[1].flag_name == '-b'
    assert not p.instances[1].flag_input
    assert p.instances[1].pos == 2

    assert p.instances[2].flag_name == '-x'
    assert not p.instances[2].flag_input
    assert p.instances[2].pos == 3

    assert p.instances[3].flag_name == '-x'
    assert p.instances[3].flag_input == 'X1'
    assert p.instances[3].pos == 4

    assert p.instances[4].flag_name == '-x'
    assert p.instances[4].flag_input == 'X2'
    assert p.instances[4].pos == 6

    assert p.instances[5].flag_name == '--yflag'
    assert not p.instances[5].flag_input
    assert p.instances[5].pos == 7

    assert p.instances[6].flag_name == '--yflag'
    assert p.instances[6].flag_input == 'Y1'
    assert p.instances[6].pos == 8

    assert p.instances[7].flag_name == '--yflag'
    assert p.instances[7].flag_input == 'Y2'
    assert p.instances[7].pos == 10

    assert p.instances[8].flag_name == '-m'
    assert p.instances[8].flag_input == 'M1'
    assert p.instances[8].pos == 11

    assert p.instances[9].flag_name == '-m'
    assert p.instances[9].flag_input == 'M2'
    assert p.instances[9].pos == 13

    assert p.instances[10].flag_name == '--mflag'
    assert p.instances[10].flag_input == 'M3'
    assert p.instances[10].pos == 14

    assert p.instances[11].flag_name == '--mflag'
    assert p.instances[11].flag_input == 'M4'
    assert p.instances[11].pos == 16

    val = p.has('a')
    assert val == True

    val = p.has('b')
    assert val == True

    val = p.has('c')
    assert val == False

    val = p.has('x')
    assert val == 'X2'

    val = p.has('y')
    assert val == 'Y2'

    val = p.has('z')
    assert val == False

    val = p.has('m')
    assert val == 'M4'

    val = p.has('n')
    assert val == False

    val = p.has('o')
    assert val == False

def test_parser4():
    p = Parser.Parser(prog)
    p.add_flag(a_flag, b_flag, c_flag, x_flag, y_flag, z_flag,
               m_flag, n_flag, o_flag)
    mode = Parser.Mode()
    mode.set_collect_if(True)
    p.add_mode(mode)

    args = [ 'PROGRAM_NAME',
             '-ab', 'A', '-bax', '-a', 'B', '-cy', 'C', '-cna', '-cnn',
             '-cnm', 'D', '-axm', 'E', '-bo', 'F', '-oaflag', 'G',
             '-o--aflag', 'H', '-zbflag', 'I', '-z--bflag', 'J' ]

    # pos                 inst. inputs
    # 1:  -a            1   1   
    # 1:  -b            2   2   
    # 2:  A             3       1
    # 3:  -b            4   3   
    # 3:  -a            5   4   
    # 3:  -x            6   5   
    # 4:  -a            7   6   
    # 5:  B             8       2
    # 6:  -c            9   7   
    # 6:  -y C          10  8   
    # 8:  -c            11  9   
    # 8:  -n a          12  10  
    # 9:  -c            13  11  
    # 9:  -n n          14  12  
    # 10: -c            15  13  
    # 10: -n m          16  14  
    # 11: D             17      3
    # 12: -a            18  15  
    # 12: -x m          19  16  
    # 13: E             20      4
    # 14: -b            21  17  
    # 14: -o F          22  18  
    # 16: -o aflag      23  19  
    # 17: G             24      5
    # 18: -o --aflag    25  20  
    # 19: H             26      6
    # 20: -z bflag      27  21  
    # 21: I             28      7
    # 22: -z --bflag    29  22  
    # 23: J             30      8

    retval = p.parse_args(args)
    assert not retval

    assert p.errors == []
    assert p.inputs == [ 'A', 'B', 'D', 'E', 'G', 'H', 'I', 'J' ]

    assert len(p.instances) == 22

    assert p.instances[0].flag_name == '-a'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 1
    assert p.instances[0].subpos == None

    assert p.instances[1].flag_name == '-b'
    assert p.instances[1].flag_input == None
    assert p.instances[1].pos == 1
    assert p.instances[1].subpos == 2

    assert p.instances[2].flag_name == '-b'
    assert p.instances[2].flag_input == None
    assert p.instances[2].pos == 3
    assert p.instances[2].subpos == None

    assert p.instances[3].flag_name == '-a'
    assert p.instances[3].flag_input == None
    assert p.instances[3].pos == 3
    assert p.instances[3].subpos == 2

    assert p.instances[4].flag_name == '-x'
    assert p.instances[4].flag_input == None
    assert p.instances[4].pos == 3
    assert p.instances[4].subpos == 3

    assert p.instances[5].flag_name == '-a'
    assert p.instances[5].flag_input == None
    assert p.instances[5].pos == 4
    assert p.instances[5].subpos == None

    assert p.instances[6].flag_name == '-c'
    assert p.instances[6].flag_input == None
    assert p.instances[6].pos == 6
    assert p.instances[6].subpos == None

    assert p.instances[7].flag_name == '-y'
    assert p.instances[7].flag_input == 'C'
    assert p.instances[7].pos == 6
    assert p.instances[7].subpos == 2

    assert p.instances[8].flag_name == '-c'
    assert p.instances[8].flag_input == None
    assert p.instances[8].pos == 8
    assert p.instances[8].subpos == None

    assert p.instances[9].flag_name == '-n'
    assert p.instances[9].flag_input == 'a'
    assert p.instances[9].pos == 8
    assert p.instances[9].subpos == 2

    assert p.instances[10].flag_name == '-c'
    assert p.instances[10].flag_input == None
    assert p.instances[10].pos == 9
    assert p.instances[10].subpos == None

    assert p.instances[11].flag_name == '-n'
    assert p.instances[11].flag_input == 'n'
    assert p.instances[11].pos == 9
    assert p.instances[11].subpos == 2

    assert p.instances[12].flag_name == '-c'
    assert p.instances[12].flag_input == None
    assert p.instances[12].pos == 10
    assert p.instances[12].subpos == None

    assert p.instances[13].flag_name == '-n'
    assert p.instances[13].flag_input == 'm'
    assert p.instances[13].pos == 10
    assert p.instances[13].subpos == 2

    assert p.instances[14].flag_name == '-a'
    assert p.instances[14].flag_input == None
    assert p.instances[14].pos == 12
    assert p.instances[14].subpos == None

    assert p.instances[15].flag_name == '-x'
    assert p.instances[15].flag_input == 'm'
    assert p.instances[15].pos == 12
    assert p.instances[15].subpos == 2

    assert p.instances[16].flag_name == '-b'
    assert p.instances[16].flag_input == None
    assert p.instances[16].pos == 14
    assert p.instances[16].subpos == None

    assert p.instances[17].flag_name == '-o'
    assert p.instances[17].flag_input == 'F'
    assert p.instances[17].pos == 14
    assert p.instances[17].subpos == 2

    assert p.instances[18].flag_name == '-o'
    assert p.instances[18].flag_input == 'aflag'
    assert p.instances[18].pos == 16
    assert p.instances[18].subpos == None

    assert p.instances[19].flag_name == '-o'
    assert p.instances[19].flag_input == '--aflag'
    assert p.instances[19].pos == 18
    assert p.instances[19].subpos == None

    assert p.instances[20].flag_name == '-z'
    assert p.instances[20].flag_input == 'bflag'
    assert p.instances[20].pos == 20
    assert p.instances[20].subpos == None

    assert p.instances[21].flag_name == '-z'
    assert p.instances[21].flag_input == '--bflag'
    assert p.instances[21].pos == 22
    assert p.instances[21].subpos == None

def test_parser5():
    p = Parser.Parser(prog)
    p.add_flag(a_flag, x_flag, m_flag)

    mode = Parser.Mode()
    mode.add_flag(b_flag, y_flag, n_flag)
    p.add_mode(mode)

    Qmode = Parser.Mode('Q')
    Qmode.add_flag(c_flag, z_flag, o_flag)
    p.add_mode(Qmode)

    args = [ 'PROGRAM_NAME',
             'Q', '-ax', '-am', 'A', '-cz', '-co', 'C' ]

    retval = p.parse_args(args)
    assert not retval

    assert p.errors == []
    assert p.inputs == []

    assert len(p.instances) == 8

    assert p.instances[0].flag_name == '-a'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 2
    assert p.instances[0].subpos == None

    assert p.instances[1].flag_name == '-x'
    assert p.instances[1].flag_input == None
    assert p.instances[1].pos == 2
    assert p.instances[1].subpos == 2

    assert p.instances[2].flag_name == '-a'
    assert p.instances[2].flag_input == None
    assert p.instances[2].pos == 3
    assert p.instances[2].subpos == None

    assert p.instances[3].flag_name == '-m'
    assert p.instances[3].flag_input == 'A'
    assert p.instances[3].pos == 3
    assert p.instances[3].subpos == 2

    assert p.instances[4].flag_name == '-c'
    assert p.instances[4].flag_input == None
    assert p.instances[4].pos == 5
    assert p.instances[4].subpos == None

    assert p.instances[5].flag_name == '-z'
    assert p.instances[5].flag_input == None
    assert p.instances[5].pos == 5
    assert p.instances[5].subpos == 2

    assert p.instances[6].flag_name == '-c'
    assert p.instances[6].flag_input == None
    assert p.instances[6].pos == 6
    assert p.instances[6].subpos == None

    assert p.instances[7].flag_name == '-o'
    assert p.instances[7].flag_input == 'C'
    assert p.instances[7].pos == 6
    assert p.instances[7].subpos == 2


    args = [ 'PROGRAM_NAME',
             '-ax', '-am', 'A', '-by', '-bn', 'B' ]

    retval = p.parse_args(args)
    assert not retval

    assert p.errors == []
    assert p.inputs == []

    assert len(p.instances) == 8

    assert p.instances[0].flag_name == '-a'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 1
    assert p.instances[0].subpos == None

    assert p.instances[1].flag_name == '-x'
    assert p.instances[1].flag_input == None
    assert p.instances[1].pos == 1
    assert p.instances[1].subpos == 2

    assert p.instances[2].flag_name == '-a'
    assert p.instances[2].flag_input == None
    assert p.instances[2].pos == 2
    assert p.instances[2].subpos == None

    assert p.instances[3].flag_name == '-m'
    assert p.instances[3].flag_input == 'A'
    assert p.instances[3].pos == 2
    assert p.instances[3].subpos == 2

    assert p.instances[4].flag_name == '-b'
    assert p.instances[4].flag_input == None
    assert p.instances[4].pos == 4
    assert p.instances[4].subpos == None

    assert p.instances[5].flag_name == '-y'
    assert p.instances[5].flag_input == None
    assert p.instances[5].pos == 4
    assert p.instances[5].subpos == 2

    assert p.instances[6].flag_name == '-b'
    assert p.instances[6].flag_input == None
    assert p.instances[6].pos == 5
    assert p.instances[6].subpos == None

    assert p.instances[7].flag_name == '-n'
    assert p.instances[7].flag_input == 'B'
    assert p.instances[7].pos == 5
    assert p.instances[7].subpos == 2


    # use a 'Q' mode flag (c, z, o)
    args = [ 'PROGRAM_NAME',
             '-c', '-z', '-oA', '-o', 'B',
             '--cflag', '--zflag', '--oflag',
             '--cflag=C', '--zflag=D', '--oflag=E' ]

    retval = p.parse_args(args)

    assert retval

    assert len(p.errors) == 11

    assert p.errors[0].errno == 1020
    assert p.errors[0].pos == 1
    assert p.errors[0].arg == '-c'

    assert p.errors[1].errno == 1020
    assert p.errors[1].pos == 2
    assert p.errors[1].arg == '-z'

    assert p.errors[2].errno == 1020
    assert p.errors[2].pos == 3
    assert p.errors[2].arg == '-o'

    assert p.errors[3].errno == 1020
    assert p.errors[3].pos == 4
    assert p.errors[3].arg == '-o'

    assert p.errors[4].errno == 1021
    assert p.errors[4].pos == 5
    assert p.errors[4].arg == 'B'

    assert p.errors[5].errno == 1020
    assert p.errors[5].pos == 6
    assert p.errors[5].arg == '--cflag'

    assert p.errors[6].errno == 1020
    assert p.errors[6].pos == 7
    assert p.errors[6].arg == '--zflag'

    assert p.errors[7].errno == 1020
    assert p.errors[7].pos == 8
    assert p.errors[7].arg == '--oflag'

    assert p.errors[8].errno == 1020
    assert p.errors[8].pos == 9
    assert p.errors[8].arg == '--cflag'

    assert p.errors[9].errno == 1020
    assert p.errors[9].pos == 10
    assert p.errors[9].arg == '--zflag'

    assert p.errors[10].errno == 1020
    assert p.errors[10].pos == 11
    assert p.errors[10].arg == '--oflag'

    assert p.inputs == []
    assert p.instances == []


    # use a default mode flag (b, y, n)
    args = [ 'PROGRAM_NAME',
             'Q', '-b', '-y', '-nA', '-n', 'B',
             '--bflag', '--yflag', '--nflag',
             '--bflag=C', '--yflag=D', '--nflag=E' ]

    retval = p.parse_args(args)

    assert retval

    assert len(p.errors) == 11

    assert p.errors[0].errno == 1020
    assert p.errors[0].pos == 2
    assert p.errors[0].arg == '-b'

    assert p.errors[1].errno == 1020
    assert p.errors[1].pos == 3
    assert p.errors[1].arg == '-y'

    assert p.errors[2].errno == 1020
    assert p.errors[2].pos == 4
    assert p.errors[2].arg == '-n'

    assert p.errors[3].errno == 1020
    assert p.errors[3].pos == 5
    assert p.errors[3].arg == '-n'

    assert p.errors[4].errno == 1021
    assert p.errors[4].pos == 6
    assert p.errors[4].arg == 'B'

    assert p.errors[5].errno == 1020
    assert p.errors[5].pos == 7
    assert p.errors[5].arg == '--bflag'

    assert p.errors[6].errno == 1020
    assert p.errors[6].pos == 8
    assert p.errors[6].arg == '--yflag'

    assert p.errors[7].errno == 1020
    assert p.errors[7].pos == 9
    assert p.errors[7].arg == '--nflag'

    assert p.errors[8].errno == 1020
    assert p.errors[8].pos == 10
    assert p.errors[8].arg == '--bflag'

    assert p.errors[9].errno == 1020
    assert p.errors[9].pos == 11
    assert p.errors[9].arg == '--yflag'

    assert p.errors[10].errno == 1020
    assert p.errors[10].pos == 12
    assert p.errors[10].arg == '--nflag'

    assert p.inputs == []
    assert p.instances == []

def test_parser6():
    p = Parser.Parser(prog)
    p.add_flag(a_flag, x_flag, m_flag)

    mode = Parser.Mode()
    mode.add_flag(b_flag, y_flag, n_flag)
    p.add_mode(mode)

    Qmode = Parser.Mode('Q')
    Qmode.add_flag(c_flag, z_flag, o_flag)
    p.add_mode(Qmode)

    args = [ 'PROGRAM_NAME',
             'A', '-P', '--Pflag', 'I' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 1
    assert p.errors[0].errno == 1000
    assert p.errors[0].arg == 'A'

    assert p.instances == []
    assert p.inputs == []


    args = [ 'PROGRAM_NAME',
             '-m', '--mflag=', '-a', '-m' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 3
    assert p.errors[0].errno == 1010
    assert p.errors[0].pos == 1
    assert p.errors[0].arg == '-m'

    assert p.errors[1].errno == 1010
    assert p.errors[1].pos == 2
    assert p.errors[1].arg == '--mflag'

    assert p.errors[2].errno == 1010
    assert p.errors[2].pos == 4
    assert p.errors[2].arg == '-m'

    assert len(p.instances) == 1
    assert p.instances[0].flag_name == '-a'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 3
    assert p.instances[0].subpos == None

    assert p.inputs == []


    args = [ 'PROGRAM_NAME',
             '-aX', '--aflag=Y', '--aflag=', '-a', 'Y', '-I', '--Iflag' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 6
    assert p.errors[0].errno == 1011
    assert p.errors[0].pos == 1
    assert p.errors[0].arg == '-a'
    assert p.errors[0].ref == 'X'

    assert p.errors[1].errno == 1011
    assert p.errors[1].pos == 2
    assert p.errors[1].arg == '--aflag'
    assert p.errors[1].ref == 'Y'

    assert p.errors[2].errno == 1012
    assert p.errors[2].pos == 3
    assert p.errors[2].arg == '--aflag'

    assert p.errors[3].errno == 1021
    assert p.errors[3].pos == 5
    assert p.errors[3].arg == 'Y'

    assert p.errors[4].errno == 1020
    assert p.errors[4].pos == 6
    assert p.errors[4].arg == '-I'

    assert p.errors[5].errno == 1020
    assert p.errors[5].pos == 7
    assert p.errors[5].arg == '--Iflag'

    assert len(p.instances) == 1
    assert p.instances[0].flag_name == '-a'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 4
    assert p.instances[0].subpos == None

def test_parser7():
    p = Parser.Parser(prog)
    p.add_option('-o', '--oflag', match=r'[a-z]+[0-9]$')
    p.add_mandatory('-m', '--mflag', match=icheck)

    mode = Parser.Mode()
    mode.set_collect_if(True)
    p.add_mode(mode)

    Qmode = Parser.Mode('Q')
    Qmode.set_collect_if(icheck)
    p.add_mode(Qmode)

    Rmode = Parser.Mode('R')
    Rmode.set_collect_if(r'(abc|def|ghi)?[0-9]$')
    p.add_mode(Rmode)


    args = [ 'PROGRAM_NAME',
              '-o', '-oa1', '-o', 'b2', '--oflag', '--oflag', 'cd3',
              '--oflag=efgh4',
              '-o1', '-o', 'a', '--oflag', 'A1', '--oflag=Aa1' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 4

    assert p.errors[0].errno == 1013
    assert p.errors[0].pos == 9
    assert p.errors[0].arg == '-o'
    assert p.errors[0].ref == '1'

    assert p.errors[1].errno == 1013
    assert p.errors[1].pos == 10
    assert p.errors[1].arg == '-o'
    assert p.errors[1].ref == 'a'

    assert p.errors[2].errno == 1013
    assert p.errors[2].pos == 12
    assert p.errors[2].arg == '--oflag'
    assert p.errors[2].ref == 'A1'

    assert p.errors[3].errno == 1013
    assert p.errors[3].pos == 14
    assert p.errors[3].arg == '--oflag'
    assert p.errors[3].ref == 'Aa1'

    assert len(p.instances) == 6

    assert p.instances[0].flag_name == '-o'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 1
    assert p.instances[0].subpos == None

    assert p.instances[1].flag_name == '-o'
    assert p.instances[1].flag_input == 'a1'
    assert p.instances[1].pos == 2
    assert p.instances[1].subpos == None

    assert p.instances[2].flag_name == '-o'
    assert p.instances[2].flag_input == 'b2'
    assert p.instances[2].pos == 3
    assert p.instances[2].subpos == None

    assert p.instances[3].flag_name == '--oflag'
    assert p.instances[3].flag_input == None
    assert p.instances[3].pos == 5
    assert p.instances[3].subpos == None

    assert p.instances[4].flag_name == '--oflag'
    assert p.instances[4].flag_input == 'cd3'
    assert p.instances[4].pos == 6
    assert p.instances[4].subpos == None

    assert p.instances[5].flag_name == '--oflag'
    assert p.instances[5].flag_input == 'efgh4'
    assert p.instances[5].pos == 8
    assert p.instances[5].subpos == None

    assert p.inputs == []


    args = [ 'PROGRAM_NAME',
             '-m', 'A', '-mB', '--mflag', 'A', '--mflag=B',
             '-m1100', '-m', '1200', '--mflag', '1210', '--mflag=1211',
             '-m1212', '-I', 'J', '--Kflag' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 5

    assert p.errors[0].errno == 1100
    assert p.errors[0].pos == 'pos1'
    assert p.errors[0].arg == 'arg1'
    assert p.errors[0].ref == 'ref1'
    assert p.errors[0].max == 'max1'

    assert p.errors[1].errno == 1200
    assert p.errors[1].pos == 'pos2'
    assert p.errors[1].arg == 'arg2'
    assert p.errors[1].ref == 'ref2'

    assert p.errors[2].errno == 1210
    assert p.errors[2].pos == 'pos3'
    assert p.errors[2].arg == 'arg3'
    assert p.errors[2].ref == 'ref3'
    assert p.errors[2].spec == 'spec1'

    assert p.errors[3].errno == 1211
    assert p.errors[3].pos == 'pos4'
    assert p.errors[3].arg == 'arg4'
    assert p.errors[3].ref == 'ref4'
    assert p.errors[3].spec == 'spec2'

    assert p.errors[4].errno == 1212
    assert p.errors[4].pos == 'pos5'
    assert p.errors[4].arg == 'arg5'
    assert p.errors[4].ref == 'ref5'
    assert p.errors[4].spec == 'spec3'

    assert len(p.instances) == 4

    assert p.instances[0].flag_name == '-m'
    assert p.instances[0].flag_input == 1
    assert p.instances[0].pos == 1
    assert p.instances[0].subpos == None

    assert p.instances[1].flag_name == '-m'
    assert p.instances[1].flag_input == 2
    assert p.instances[1].pos == 3
    assert p.instances[1].subpos == None

    assert p.instances[2].flag_name == '--mflag'
    assert p.instances[2].flag_input == 1
    assert p.instances[2].pos == 4
    assert p.instances[2].subpos == None

    assert p.instances[3].flag_name == '--mflag'
    assert p.instances[3].flag_input == 2
    assert p.instances[3].pos == 6
    assert p.instances[3].subpos == None

    assert p.inputs == [ '-I', 'J', '--Kflag' ]


    args = [ 'PROGRAM_NAME',
             'Q', '-m', 'A', '--mflag=B',
             'A', 'B', '1100', '1200', '1210', '1211', '1212' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 5

    assert p.errors[0].errno == 1100
    assert p.errors[0].pos == 'pos1'
    assert p.errors[0].arg == 'arg1'
    assert p.errors[0].ref == 'ref1'
    assert p.errors[0].max == 'max1'

    assert p.errors[1].errno == 1200
    assert p.errors[1].pos == 'pos2'
    assert p.errors[1].arg == 'arg2'
    assert p.errors[1].ref == 'ref2'

    assert p.errors[2].errno == 1210
    assert p.errors[2].pos == 'pos3'
    assert p.errors[2].arg == 'arg3'
    assert p.errors[2].ref == 'ref3'
    assert p.errors[2].spec == 'spec1'

    assert p.errors[3].errno == 1211
    assert p.errors[3].pos == 'pos4'
    assert p.errors[3].arg == 'arg4'
    assert p.errors[3].ref == 'ref4'
    assert p.errors[3].spec == 'spec2'

    assert p.errors[4].errno == 1212
    assert p.errors[4].pos == 'pos5'
    assert p.errors[4].arg == 'arg5'
    assert p.errors[4].ref == 'ref5'
    assert p.errors[4].spec == 'spec3'

    assert len(p.instances) == 2

    assert p.instances[0].flag_name == '-m'
    assert p.instances[0].flag_input == 1
    assert p.instances[0].pos == 2
    assert p.instances[0].subpos == None

    assert p.instances[1].flag_name == '--mflag'
    assert p.instances[1].flag_input == 2
    assert p.instances[1].pos == 4
    assert p.instances[1].subpos == None

    assert p.inputs == [ 1, 2 ]


    args = [ 'PROGRAM_NAME',
             'R', '-o', 'a1', '--oflag=bc2',
             'abc1', 'def3', 'ghi0', '1', '7', '9',
             'abcdef1', 'abcdefghi1', '(abc|def|ghi)?[0-9]$',
             'aabc1', 'abc12', '12', 'a' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.instances) == 2

    assert p.instances[0].flag_name == '-o'
    assert p.instances[0].flag_input == 'a1'
    assert p.instances[0].pos == 2
    assert p.instances[0].subpos == None

    assert p.instances[1].flag_name == '--oflag'
    assert p.instances[1].flag_input == 'bc2'
    assert p.instances[1].pos == 4
    assert p.instances[1].subpos == None

    assert p.inputs == [ 'abc1', 'def3', 'ghi0', '1', '7', '9' ]

    assert len(p.errors) == 7

    assert p.errors[0].errno == 1021
    assert p.errors[0].pos == 11
    assert p.errors[0].arg == 'abcdef1'

    assert p.errors[1].errno == 1021
    assert p.errors[1].pos == 12
    assert p.errors[1].arg == 'abcdefghi1'

    assert p.errors[2].errno == 1021
    assert p.errors[2].pos == 13
    assert p.errors[2].arg == '(abc|def|ghi)?[0-9]$'

    assert p.errors[3].errno == 1021
    assert p.errors[3].pos == 14
    assert p.errors[3].arg == 'aabc1'

    assert p.errors[4].errno == 1021
    assert p.errors[4].pos == 15
    assert p.errors[4].arg == 'abc12'

    assert p.errors[5].errno == 1021
    assert p.errors[5].pos == 16
    assert p.errors[5].arg == '12'

    assert p.errors[6].errno == 1021
    assert p.errors[6].pos == 17
    assert p.errors[6].arg == 'a'

def test_parser8():
    p = Parser.Parser(prog)
    p.add_bare('-a')
    p.add_bare('--bflag')
    p.add_mandatory('-m')
    p.add_mandatory('--mflag')


    args = [ 'PROGRAM_NAME',
             '-ax', '-A', '--bflag', '-B', '-my', '-C', '-m', 'z', '-D',
             '--mflag=p', '-E', '--mflag', 'q', '-F', '-G',
             '-ar', '--A', '--bflag', '--B', '-ms', '--C', '-m', 't', '--D',
             '--mflag=u', '--E', '--mflag', 'v', '--F', '--G' ]


    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 16

    assert p.errors[0].errno == 1011
    assert p.errors[0].pos == 1
    assert p.errors[0].arg == '-a'
    assert p.errors[0].ref == 'x'

    assert p.errors[1].errno == 1020
    assert p.errors[1].pos == 2
    assert p.errors[1].arg == '-A'

    assert p.errors[2].errno == 1020
    assert p.errors[2].pos == 4
    assert p.errors[2].arg == '-B'

    assert p.errors[3].errno == 1020
    assert p.errors[3].pos == 6
    assert p.errors[3].arg == '-C'

    assert p.errors[4].errno == 1020
    assert p.errors[4].pos == 9
    assert p.errors[4].arg == '-D'

    assert p.errors[5].errno == 1020
    assert p.errors[5].pos == 11
    assert p.errors[5].arg == '-E'

    assert p.errors[6].errno == 1020
    assert p.errors[6].pos == 14
    assert p.errors[6].arg == '-F'

    assert p.errors[7].errno == 1020
    assert p.errors[7].pos == 15
    assert p.errors[7].arg == '-G'

    assert p.errors[8].errno == 1011
    assert p.errors[8].pos == 16
    assert p.errors[8].arg == '-a'
    assert p.errors[8].ref == 'r'

    assert p.errors[9].errno == 1020
    assert p.errors[9].pos == 17
    assert p.errors[9].arg == '--A'

    assert p.errors[10].errno == 1020
    assert p.errors[10].pos == 19
    assert p.errors[10].arg == '--B'

    assert p.errors[11].errno == 1020
    assert p.errors[11].pos == 21
    assert p.errors[11].arg == '--C'

    assert p.errors[12].errno == 1020
    assert p.errors[12].pos == 24
    assert p.errors[12].arg == '--D'

    assert p.errors[13].errno == 1020
    assert p.errors[13].pos == 26
    assert p.errors[13].arg == '--E'

    assert p.errors[14].errno == 1020
    assert p.errors[14].pos == 29
    assert p.errors[14].arg == '--F'

    assert p.errors[15].errno == 1020
    assert p.errors[15].pos == 30
    assert p.errors[15].arg == '--G'


    assert len(p.instances) == 10

    assert p.instances[0].flag_name == '--bflag'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 3
    assert p.instances[0].subpos == None

    assert p.instances[1].flag_name == '-m'
    assert p.instances[1].flag_input == 'y'
    assert p.instances[1].pos == 5
    assert p.instances[1].subpos == None

    assert p.instances[2].flag_name == '-m'
    assert p.instances[2].flag_input == 'z'
    assert p.instances[2].pos == 7
    assert p.instances[2].subpos == None

    assert p.instances[3].flag_name == '--mflag'
    assert p.instances[3].flag_input == 'p'
    assert p.instances[3].pos == 10
    assert p.instances[3].subpos == None

    assert p.instances[4].flag_name == '--mflag'
    assert p.instances[4].flag_input == 'q'
    assert p.instances[4].pos == 12
    assert p.instances[4].subpos == None

    assert p.instances[5].flag_name == '--bflag'
    assert p.instances[5].flag_input == None
    assert p.instances[5].pos == 18
    assert p.instances[5].subpos == None

    assert p.instances[6].flag_name == '-m'
    assert p.instances[6].flag_input == 's'
    assert p.instances[6].pos == 20
    assert p.instances[6].subpos == None

    assert p.instances[7].flag_name == '-m'
    assert p.instances[7].flag_input == 't'
    assert p.instances[7].pos == 22
    assert p.instances[7].subpos == None

    assert p.instances[8].flag_name == '--mflag'
    assert p.instances[8].flag_input == 'u'
    assert p.instances[8].pos == 25
    assert p.instances[8].subpos == None

    assert p.instances[9].flag_name == '--mflag'
    assert p.instances[9].flag_input == 'v'
    assert p.instances[9].pos == 27
    assert p.instances[9].subpos == None


    assert p.inputs == []

def test_parser9():
    p = Parser.Parser(prog)
    p.add_flag(a_flag, x_flag, m_flag)

    mode = Parser.Mode()
    mode.add_flag(b_flag, y_flag, n_flag)
    p.add_mode(mode)

    Qmode = Parser.Mode('P', 'Q')
    Qmode.add_flag(c_flag, z_flag, o_flag)
    p.add_mode(Qmode)

    args = [ 'PROGRAM_NAME',
             'P', 'Q', '-c', '-b' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 2
    assert p.errors[0].errno == 1021
    assert p.errors[0].arg == 'Q'

    assert p.errors[1].errno == 1020
    assert p.errors[1].arg == '-b'

    assert len(p.instances) == 1
    assert p.instances[0].flag_name == '-c'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 3
    assert p.instances[0].subpos == None

    assert p.inputs == []


    args = [ 'PROGRAM_NAME',
             'Q', 'P', '-c', '-b' ]

    retval = p.parse_args(args)
    assert retval

    assert len(p.errors) == 2
    assert p.errors[0].errno == 1021
    assert p.errors[0].arg == 'P'

    assert p.errors[1].errno == 1020
    assert p.errors[1].arg == '-b'

    assert len(p.instances) == 1
    assert p.instances[0].flag_name == '-c'
    assert p.instances[0].flag_input == None
    assert p.instances[0].pos == 3
    assert p.instances[0].subpos == None

    assert p.inputs == []

