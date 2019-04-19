
import pytest
import re
from pathlib import Path
from time import sleep

from alnitak import config
from alnitak.api import cloudflare
from alnitak.tests import setup
from alnitak import prog as Prog
from alnitak import exceptions as Except


@pytest.fixture(scope="module")
def cloudflare_api(request):
    return Path(request.fspath.dirname) / 'cloudflare.api'

def api_file_exists(cloudflare_api):
    if cloudflare_api.exists():
        return True
    return False

def get_domain(api_path):
    with open(str(api_path), 'r') as file:
        lines = file.read().splitlines()

    domain = None
    for l in lines:
        m = re.match(r'\s*#.*domain:\s*(?P<domain>\S+)\s*$', l)
        if m:
            domain = m.group('domain')
    return domain


def test_cloudflare(cloudflare_api):
    if not api_file_exists(cloudflare_api):
        pytest.skip("no cloudflare.api file")

    # need the domain
    domain = get_domain(cloudflare_api)
    assert domain

    s = setup.Init(keep=True)
    s.create_cloudflare_config(cloudflare_api, domain)

    prog = setup.create_state_obj(s, config=s.configC1)

    # need this to log if create_state_obj set 'log=True', otherwise this will
    # do nothing.
    prog.log.init(prog.name, prog.version, prog.timenow)


    retval = config.read(prog)
    assert retval == Prog.RetVal.ok

    t_a2 = setup.create_tlsa_obj('211', '53527', 'tcp', domain)
    t_a1 = setup.create_tlsa_obj('311', '53527', 'tcp', domain)

    assert len(prog.target_list) == 1

    target = prog.target_list[0]

    assert len(target.tlsa) == 2
    assert t_a1 in target.tlsa
    assert t_a2 in target.tlsa
    tlsa1 = target.tlsa[0]
    tlsa2 = target.tlsa[1]

    api = target.api

    assert api.domain == domain
    assert len(api.email) > 0
    assert len(api.key) > 0

    hash211 = s.hash['a.com']['cert1'][211]
    hash311 = s.hash['a.com']['cert1'][311]

    cloudflare.api_publish(prog, api, tlsa1, hash211)
    cloudflare.api_publish(prog, api, tlsa2, hash311)
    # error encountered: Except.DNSProcessingError
    # record is already up: Except.DNSSkipProcessing

    sleep(3)

    records211 = cloudflare.api_read(prog, api, tlsa1)
    records311 = cloudflare.api_read(prog, api, tlsa2)
    # error encountered: Except.DNSProcessingError
    # record is not up: Except.DNSNotLive

    assert len(records211) == 1
    assert hash211 in records211

    assert len(records311) == 1
    assert hash311 in records311

    id211 = records211[hash211]
    id311 = records311[hash311]

    sleep(3)

    cloudflare.api_delete(prog, api, tlsa1, id211)
    cloudflare.api_delete(prog, api, tlsa2, id311)
    # error encountered: Except.DNSProcessingError

    sleep(3)

    with pytest.raises(Except.DNSNotLive) as ex:
        cloudflare.api_read(prog, api, tlsa1)

    with pytest.raises(Except.DNSNotLive) as ex:
        cloudflare.api_read(prog, api, tlsa2)

