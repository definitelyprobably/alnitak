
import re
import shlex

from alnitak import exceptions as Except
from alnitak import prog as Prog


def get_errors(response):
    """Extract error messages from the JSON response.

    Argument should be a dict. If a key called 'errors' is found, it
    should be a list:
        { 'errors': [ ... ], ... }

    The objects in the list should be a dict. If this dict has keys
    'message' and 'code', then their values will be added to a list
    of error messages to return:
        { 'message': 'X', 'code': N }  -->  [ [N, 'X'] ]

    If the dict has a key 'error_chain', then its value should be a
    list of dicts also containing 'message' and 'code' as keys; these
    will also be added to the list of error messages to return:
        { 'message': 'X',
          'code': N,
          'error_chain': [ {'message': 'Y', 'code': P} ] }
    will construct:
        [ [P, 'Y'], [N, 'X'] ]

    The complete error list to return will be constructed from all
    such list items of 'errors' found in the argument dict in this
    way.

    Args:
        response (dict): JSON response from a 'requests' call.

    Returns:
        list(list(int, str)): return list a lists containing an (int)
            error code and (str) message.
    """
    errors = []
    for a in response['errors']:
        try:
            temp = [ [ b['code'], b['message'] ] for b in a['error_chain'] ]
        except KeyError:
            temp = []

        errors += temp

        try:
            errors += [ [a['code'], a['message']] ]
        except KeyError:
            pass

    return errors

def get_zone(prog, api):
    """Get the zone ID for the domain.

    This function will get a zone ID for the domain. It will also initialize
    the CloudFlare.CloudFlare object if the Cloudflare python package is
    present, which future read/publish/delete functions will use. Otherwise,
    we'll just use raw HTTP calls directly.

    Args:
        prog (State): not changed.
        api (ApiCloudflare): contains Cloudflare login details.

    Raises:
        DNSProcessingError: raised for all errors encountered.
    """

    # if zone is not empty, then we have already initialized
    if api.zone:
        return

    prog.log.info2("  + need a zone ID for {}".format(api.domain))

    params = {'name': api.domain}

    # try native method
    try:
        from CloudFlare import CloudFlare
        from CloudFlare.exceptions import CloudFlareAPIError

        prog.log.info2("  + using native call(s)...")

        api.cloudflare = CloudFlare(email=api.email, token=api.key)

        zones = api.cloudflare.zones.get(params=params)
        for z in zones:
            if z['name'] == api.domain:
                api.zone = z['id']
                break

        if not api.zone:
            raise Except.DNSProcessingError(
                    "Cloudflare: no zone with domain '{}' found".format(
                                                                api.domain))

        # all done; return explicitly to avoid running the fallback code
        return

    # use fallback method
    except ModuleNotFoundError:
        pass

    except CloudFlareAPIError as exc:
        if len(exc) > 0:
            errs = []
            for e in exc:
                errs += [ "Cloudflare error {}: {}".format(int(e), str(e)) ]
            raise Except.DNSProcessingError(errs)
        else:
            raise Except.DNSProcessingError(
                    "Cloudflare error {}: {}".format(int(exc), str(exc)) )
    except KeyError:
        raise Except.DNSProcessingError("Cloudflare: zone ID not found")


    # the fallback method:
    prog.log.info2("  + using fallback call(s)...")

    import requests

    headers = { "X-Auth-Email": api.email,
                "X-Auth-Key": api.key,
                "Content-Type": "application/json" }
    try:
        r = requests.get("https://api.cloudflare.com/client/v4/zones",
                                                params=params, headers=headers)
    except ConnectionError:
        raise Except.DNSProcessingError("connection error encountered")
    except requests.exceptions.Timeout:
        raise Except.DNSProcessingError("request timed out")
    except requests.exceptions.TooManyRedirects:
        raise Except.DNSProcessingError("too many redirects")
    except requests.exceptions.RequestException as ex:
        raise Except.DNSProcessingError("{}".format(ex))

    prog.log.info3("  + HTTP response: {}".format(r.status_code))

    response = r.json()
    prog.log.info3("  + JSON response: {}".format(response))

    errors = get_errors(response)
    if errors:
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code < 600:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError(
                                        "Cloudflare4 JSON response failure")

    try:
        for z in response['result']:
            if z['name'] == api.domain:
                api.zone = z['id']
                break

        if not api.zone:
            raise Except.DNSProcessingError(
                    "Cloudflare: no zone with domain '{}' found".format(
                                                                api.domain))
    except KeyError:
        raise Except.DNSProcessingError("Cloudflare: zone ID not found")

    prog.log.info2("  + zone ID retrieved: '...({})'".format(len(api.zone)))



def api_delete(prog, api, tlsa, id):
    """Delete a DANE TLSA record.

    Args:
        prog (State): not changed.
        api (ApiCloudflare): contains Cloudflare login details.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        id (str): The Cloudflare ID of the record to delete.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
    """
    get_zone(prog, api)

    if api.cloudflare:
        cloudflare_native_delete(prog, api, tlsa, id)
    else:
        cloudflare_fallback_delete(prog, api, tlsa, id)

def cloudflare_native_delete(prog, api, tlsa, id):
    """Delete a DANE TLSA record using Cloudflare's python API.

    Args:
        prog (State): not changed.
        api (ApiCloudflare): contains Cloudflare login details.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        id (str): The Cloudflare ID of the record to delete.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
    """
    prog.log.info2(
            "  + deleting TLSA record for {} (native)".format(tlsa.pstr()))

    from CloudFlare.exceptions import CloudFlareAPIError

    try:
        api.cloudflare.zones.dns_records.delete(api.zone, id)
        prog.log.info2("  + deleting record: success")
    except CloudFlareAPIError as exc:
        if len(exc) > 0:
            errs = []
            for e in exc:
                errs += [ "Cloudflare error {}: {}".format(int(e), str(e)) ]
            raise Except.DNSProcessingError(errs)
        else:
            raise Except.DNSProcessingError(
                    "Cloudflare error {}: {}".format(int(exc), str(exc)) )

def cloudflare_fallback_delete(prog, api, tlsa, id):
    """Delete a DANE TLSA record using Cloudflare's RESTful API.

    Args:
        prog (State): not changed.
        api (ApiCloudflare4): contains Cloudflare4 login details.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        id (str): The Cloudflare ID of the record to delete.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
    """
    prog.log.info2(
            "  + deleting TLSA record for {} (fallback)".format(tlsa.pstr()))

    import requests

    headers = { "X-Auth-Email": api.email,
                "X-Auth-Key": api.key,
                "Content-Type": "application/json" }

    try:
        r = requests.delete("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}".format(api.zone, id), headers=headers)
    except ConnectionError:
        raise Except.DNSProcessingError("connection error encountered")
    except requests.exceptions.Timeout:
        raise Except.DNSProcessingError("request timed out")
    except requests.exceptions.TooManyRedirects:
        raise Except.DNSProcessingError("too many redirects")
    except requests.exceptions.RequestException as ex:
        raise Except.DNSProcessingError("{}".format(ex))

    prog.log.info3("  + HTTP response: {}".format(r.status_code))

    response = r.json()
    prog.log.info3("  + JSON response: {}".format(
                        str(response).replace(api.key, '<redacted>')) )

    errors = get_errors(response)
    if errors:
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code < 600:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError("Cloudflare4 JSON response failure")



def api_publish(prog, api, tlsa, hash):
    """Create (publish) a DANE TLSA record.

    Args:
        prog (State): not changed.
        api (ApiCloudflare): contains Cloudflare login details.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        hash (str): DANE TLSA 'certificate data' (hash) to publish.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSSkipProcessing: if the record is already up.
    """
    get_zone(prog, api)

    if api.cloudflare:
        cloudflare_native_publish(prog, api, tlsa, hash)
    else:
        cloudflare_fallback_publish(prog, api, tlsa, hash)

def cloudflare_native_publish(prog, api, tlsa, hash):
    """Create (publish) a DANE TLSA record using Cloudflare's python API.

    Args:
        prog (State): not changed.
        api (ApiCloudflare): contains Cloudflare login details.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        hash (str): DANE TLSA 'certificate data' (hash) to publish.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSSkipProcessing: if the record is already up.
    """
    prog.log.info2(
            "  + publishing TLSA record for {} (native)".format(tlsa.pstr()))

    from CloudFlare.exceptions import CloudFlareAPIError

    try:
        api.cloudflare.zones.dns_records.post(api.zone,
                data={
                    "type": "TLSA",
                    "name": "_{}._{}.{}".format(tlsa.port, tlsa.protocol,
                                                tlsa.domain),
                    "data": {
                        "usage": int(tlsa.usage),
                        "selector": int(tlsa.selector),
                        "matching_type": int(tlsa.matching),
                        "certificate": hash
                        }
                    })
        prog.log.info2("  + publishing record: success")
    except CloudFlareAPIError as exc:
        if len(exc) > 0:
            errs = []
            for e in exc:
                errs += [ "Cloudflare error {}: {}".format(int(e), str(e)) ]
            raise Except.DNSProcessingError(errs)
        elif int(exc) == 81057:
            raise Except.DNSSkipProcessing(str(exc))
        else:
            raise Except.DNSProcessingError(
                    "Cloudflare error {}: {}".format(int(exc), str(exc)) )

def cloudflare_fallback_publish(prog, api, tlsa, hash):
    """Create (publish) a DANE TLSA record using Cloudflare's RESTful API.

    Args:
        prog (State): not changed.
        api (ApiCloudflare4): contains Cloudflare4 login details.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        hash (str): DANE TLSA 'certificate data' (hash) to publish.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSSkipProcessing: if the record is already up.
    """
    prog.log.info2(
            "  + publishing TLSA record for {} (fallback)".format(tlsa.pstr()))

    import requests

    headers = { "X-Auth-Email": api.email,
                "X-Auth-Key": api.key,
                "Content-Type": "application/json" }

    data = '{{ "type": "TLSA", "name": "_{}._{}.{}", "data": {{ "usage": {}, "selector": {}, "matching_type": {}, "certificate": "{}" }} }}'.format(
                    tlsa.port, tlsa.protocol, tlsa.domain, tlsa.usage,
                    tlsa.selector, tlsa.matching, hash)

    try:
        r = requests.post("https://api.cloudflare.com/client/v4/zones/{}/dns_records".format(api.zone), data=data, headers=headers)
    except ConnectionError:
        raise Except.DNSProcessingError("connection error encountered")
    except requests.exceptions.Timeout:
        raise Except.DNSProcessingError("request timed out")
    except requests.exceptions.TooManyRedirects:
        raise Except.DNSProcessingError("too many redirects")
    except requests.exceptions.RequestException as ex:
        raise Except.DNSProcessingError("{}".format(ex))

    prog.log.info3("  + HTTP response: {}".format(r.status_code))

    response = r.json()
    prog.log.info3("  + JSON response: {}".format(
                                str(response).replace(api.key, '<redacted>')) )

    errors = get_errors(response)

    # record is already up
    if len(errors) == 1 and errors[0][0] == 81057:
        # we will only accept this code if it is the only error
        # encountered
        raise Except.DNSSkipProcessing(errors[0][1])

    if errors:
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code < 600:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError("Cloudflare4 JSON response failure")



def api_read(prog, api, tlsa):
    """Get a dict of DANE TLSA records that are up.

    For example, if the following TLSA records are up:
        TLSA 3 1 1 _25._tcp.example.com  abcABC
        TLSA 3 1 1 _25._tcp.example.come defDEF
    and 'tlsa' has param '311', port '25', protocol 'tcp' and domain
    'example.com', then this function will return:
        { "abcABC": "id...", "defDEF": "id..." }
    where "id..." will be some unique ID Cloudflare has assigned to that
    record.

    Args:
        prog (State): not changed.
        api (ApiCloudflare): contains Cloudflare login details.
        tlsa (Tlsa): details of the DANE TLSA record to retrieve.

    Returns:
        dict: keys are the certificate hashes and values are the ID numbers
            assigned to it by Cloudflare.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSNotLive: if no matching records are up.
    """
    get_zone(prog, api)

    if api.cloudflare:
        return cloudflare_native_read(prog, api, tlsa)
    else:
        return cloudflare_fallback_read(prog, api, tlsa)

def cloudflare_native_read(prog, api, tlsa):
    """Get a dict of DANE TLSA records that are up.

    For example, if the following TLSA records are up:
        TLSA 3 1 1 _25._tcp.example.com  abcABC
        TLSA 3 1 1 _25._tcp.example.come defDEF
    and 'tlsa' has param '311', port '25', protocol 'tcp' and domain
    'example.com', then this function will return:
        { "abcABC": "id...", "defDEF": "id..." }
    where "id..." will be some unique ID Cloudflare has assigned to that
    record.
 
    Args:
        prog (State): not changed.
        api (ApiCloudflare): contains Cloudflare login details.
        tlsa (Tlsa): details of the DANE TLSA record to retrieve.

    Returns:
        dict: keys are the certificate hashes and values are the ID numbers
            assigned to it by Cloudflare.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSNotLive: if no matching records are up.
    """
    prog.log.info2("  + getting TLSA records for _{}._{}.{} (native)".format(
                                        tlsa.port, tlsa.protocol, tlsa.domain))

    from CloudFlare.exceptions import CloudFlareAPIError

    try:
        records = api.cloudflare.zones.dns_records.get(api.zone,
                params={
                    "type": "TLSA",
                    "name": "_{}._{}.{}".format(tlsa.port, tlsa.protocol,
                                                tlsa.domain)
                    })
        prog.log.info3("  + JSON response: {}".format(
                                str(records).replace(api.key, '<redacted>')) )
        prog.log.info2("  + retrieving records: success")
    except CloudFlareAPIError as exc:
        if len(exc) > 0:
            errs = []
            for e in exc:
                errs += [ "Cloudflare error {}: {}".format(int(e), str(e)) ]
            raise Except.DNSProcessingError(errs)
        else:
            raise Except.DNSProcessingError(
                    "Cloudflare error {}: {}".format(int(exc), str(exc)) )

    ret = { r['data']['certificate'].lower(): r['id'] for r in records
                if str(r['data']['usage']) == str(tlsa.usage)
                    and str(r['data']['selector']) == str(tlsa.selector)
                    and str(r['data']['matching_type']) == str(tlsa.matching) }
    if ret:
        return ret

    raise Except.DNSNotLive("no TLSA records found")

def cloudflare_fallback_read(prog, api, tlsa):
    """Get a dict of DANE TLSA records that are up.

    For example, if the following TLSA records are up:
        TLSA 3 1 1 _25._tcp.example.com  abcABC
        TLSA 3 1 1 _25._tcp.example.come defDEF
    and 'tlsa' has param '311', port '25', protocol 'tcp' and domain
    'example.com', then this function will return:
        { "id...": "abcABC", "id...": "defDEF" }
    where "id..." will be some unique ID Cloudflare has assigned to that
    record.
 
    Args:
        prog (State): not changed.
        api (ApiCloudflare4): contains Cloudflare4 login details.
        tlsa (Tlsa): details of the DANE TLSA record to retrieve.

    Returns:
        dict: keys are the certificate hashes and values are the ID numbers
            assigned to it by Cloudflare.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSNotLive: if no matching records are up.
    """
    prog.log.info2("  + getting TLSA records for _{}._{}.{} (fallback)".format(
                                        tlsa.port, tlsa.protocol, tlsa.domain))

    import requests

    headers = { "X-Auth-Email": api.email,
                "X-Auth-Key": api.key,
                "Content-Type": "application/json" }

    params = { "type": "TLSA",
               "name":"_{}._{}.{}".format(
                                      tlsa.port, tlsa.protocol, tlsa.domain) }

    try:
        r = requests.get("https://api.cloudflare.com/client/v4/zones/{}/dns_records".format(api.zone), params=params, headers=headers)
    except ConnectionError:
        raise Except.DNSProcessingError("connection error encountered")
    except requests.exceptions.Timeout:
        raise Except.DNSProcessingError("request timed out")
    except requests.exceptions.TooManyRedirects:
        raise Except.DNSProcessingError("too many redirects")
    except requests.exceptions.RequestException as ex:
        raise Except.DNSProcessingError("{}".format(ex))

    prog.log.info3("  + HTTP response: {}".format(r.status_code))

    response = r.json()
    prog.log.info3("  + JSON response: {}".format(
                                str(response).replace(api.key, '<redacted>')) )

    errors = get_errors(response)
    if errors:
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code < 600:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError("Cloudflare4 JSON response failure")

    ret = { r['data']['certificate'].lower(): r['id']
            for r in response['result']
                if str(r['data']['usage']) == str(tlsa.usage)
                    and str(r['data']['selector']) == str(tlsa.selector)
                    and str(r['data']['matching_type']) == str(tlsa.matching) }
    if ret:
        return ret

    raise Except.DNSNotLive("no TLSA records found")



def get_api(prog, domain, input_list, state):
    """Create an ApiCloudflare object from a config file line.

    Given an 'api = cloudflare ...' line in a config file, construct
    and return an ApiCloudflare object, or else 'None' if an error is
    encountered.

    Args:
        prog (State): not changed.
        domain (str): the domain (section) the api command is in. Note: can
            be 'None' if the api command was global.
        input_list (list(str)): a list of whitespace-delimited strings
            corresponding to the inputs following 'api = cloudflare'
            (i.e., the 'inputs' of the 'api' parameter, less the first
            'cloudflare' input).
        state (ConfigState): class to record config file errors.

    Returns:
        ApiCloudflare: creates an ApiCloudflare object from the arguments.
        None: if an error is encountered.
    """
    if len(input_list) == 0:
        state.add_error(prog, "'cloudflare' api scheme not given any data")
        return None
    elif len(input_list) > 2:
        state.add_error(prog, "'cloudflare' api scheme given superfluous data")
        return None
    elif len(input_list) == 1:
        inputs = read_cloudflare_api_file(prog, input_list[0], state)
        if not inputs:
            return None
    else:
        inputs = input_list

    api = Prog.ApiCloudflare()
    if domain:
        api.set_domain(domain)
    avail_inputs = [ is_api_cloudflare_input_email,
                     is_api_cloudflare_input_key ]

    for inp in inputs:
        for check in avail_inputs:
            if check(prog, inp, api):
                avail_inputs.remove(check)
                break
        else:
            state.add_error(
                    prog, "'cloudflare' api scheme given malformed data")
            return None

    return api

def read_cloudflare_api_file(prog, file, state):
    """Read the input file for Cloudflare login details.

    Args:
        prog (State): modified if errors encountered in opening or reading
            the file.
        file (str): the file to read.
        state (ConfigState): to record config file syntax errors.

    Returns:
        list(str): returns a list of Cloudflare login parameters
            (email and key) where a line in the file 'X = Y' is converted
            to: 'X:Y'. No checks on the input to any parameters (i.e. 'Y')
            are done here: only the list is constructed. If ANY errors
            are encountered, 'None' is returned.
    """
    try:
        with open(str(file), "r") as f:
            raw = f.read().splitlines()
    except FileNotFoundError as ex:
        prog.log.error(
                "cloudflare API file '{}' not found".format(ex.filename))
        return None
    except OSError as ex:
        prog.log.error(
                "reading cloudflare API file '{}' failed: {}".format(
                                            ex.filename, ex.strerror.lower()))
        return None

    allowed_params = {'dns_cloudflare_email': 'email',
                      'dns_cloudflare_api_key': 'key'}

    errors = False
    ret = []
    linepos = 0
    for l in raw:
        linepos += 1

        match = re.match(r'^\s*(#.*)?$', l)
        if match:
            continue

        match = re.match(
                    r'\s*(?P<param>\w+)\s*=\s*(?P<input>[^#]*)(\s*|\s#.*)$', l)
        if match:
            param = match.group('param')
            try:
                inputs = shlex.split(match.group('input'))
            except ValueError:
                state.add_error(prog, "cloudflare API file '{}' has malformed expression on line {}".format(file, linepos))
                errors = True
                continue

            if param in allowed_params:
                if len(inputs) != 1:
                    state.add_error(prog, "cloudflare API file '{}': malformed '{}' command on line {}".format(file, param, linepos))
                    errors = True
                    continue
                ret += [ '{}:{}'.format(allowed_params[param], inputs[0]) ]
                continue

            state.add_error(prog, "cloudflare API file '{}': unrecognized command on line {}: '{}'".format(file, linepos, param))
            errors = True
            continue

        state.add_error(prog, "cloudflare API file '{}' has malformed expression on line {}".format(file, linepos))
        errors = True

    if errors:
        return None

    return ret

def is_api_cloudflare_input_email(prog, inp, api):
    """Test input for Cloudflare email and set in the api object if so.

    If the input is an email input ('email:...') then set the email in the
    'api' object to it.

    Args:
        prog (State): not changed.
        inp (str): input to check.
        api (ApiCloudflare): the api object to set.

    Returns:
        bool: 'True' if email in 'api' was set to 'inp', 'False' if not.
    """
    if re.match(r'email:\S+@{}'.format(prog.tlsa_domain_regex), inp):
        api.email = inp[6:]
        return True
    return False

def is_api_cloudflare_input_key(prog, inp, api):
    """Test input for Cloudflare key and set in the api object if so.

    If the input is a key input ('key:...') then set the key in the
    'api' object to it.

    Args:
        prog (State): don't remove me because this function is looped over
            with other functions that do take this argument and use it.
        inp (str): input to check.
        api (ApiCloudflare): the api object to set.

    Returns:
        bool: 'True' if key in 'api' was set to 'inp', 'False' if not.
    """
    if re.match(r'key:\w+$', inp):
        api.key = inp[4:]
        return True
    return False


