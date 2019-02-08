
import requests

from alnitak import exceptions as Except


# For reference, the status codes are responses are as follows:
#
### Key is wrong (not enough characters):
#   400
#   {'messages': [],
#    'success': False,
#    'errors': [
#           {'error_chain': [
#                    {'message': 'Invalid format for X-Auth-Key header',
#                     'code': 6103}
#                ],
#            'message': 'Invalid request headers',
#            'code': 6003}
#        ],
#    'result': None}
#
### Key is wrong (invalid):
#   403
#   {'messages': [],
#    'success': False,
#    'errors': [
#           {'message': 'Unknown X-Auth-Key or X-Auth-Email',
#            'code': 9103}
#        ],
#    'result': None}
#
### Record is already up:
#   400
#   {'messages': [],
#    'success': False,
#    'errors': [
#           {'message': 'The record already exists.',
#            'code': 81057}
#       ],
#    'result': None}
#
#


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


def delete(prog, api, tlsa, id):
    """Delete a DANE TLSA record.

    Args:
        prog (State): not changed.
        api (ApiCloudflare4): contains Cloudflare4 login details.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        id (str): The Cloudflare ID of the record to delete.

    Returns:
        NoneType: always returns 'None'.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
    """
    prog.log.info2("  + deleting TLSA record for {}".format(tlsa.pstr()))

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
    prog.log.info3("  + JSON response: {}".format(response))

    errors = get_errors(response)
    if errors:
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code <= 599:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError("Cloudflare4 JSON response failure")



def publish(prog, api, tlsa, hash):
    """Create (publish) a DANE TLSA record.

    Args:
        prog (State): not changed.
        api (ApiCloudflare4): contains Cloudflare4 login details.
        tlsa (Tlsa): details of the DANE TLSA record to delete.
        hash (str): DANE TLSA 'certificate data' (hash) to publish.

    Returns:
        NoneType: always returns 'None'.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSSkipProcessing: if the record is already up.
    """
    prog.log.info2("  + publishing TLSA record for {}".format(tlsa.pstr()))

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
    prog.log.info3("  + JSON response: {}".format(response))

    errors = get_errors(response)

    # record is already up
    if len(errors) == 1 and errors[0][0] == 81057:
        # we will only accept this code if it is the only error
        # encountered
        raise Except.DNSSkipProcessing(errors[0][1])

    if errors:
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code <= 599:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError("Cloudflare4 JSON response failure")



def read(prog, api, tlsa):
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
        NoneType: always returns 'None'.

    Raises:
        DNSProcessingError: if an error ocurred at any point that should
            cause the Alnitak to exit with an error exit code.
        DNSNotLive: if no matching records are up.
    """
    prog.log.info2("  + getting TLSA records for _{}._{}.{}".format(
                                        tlsa.port, tlsa.protocol, tlsa.domain))

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
    prog.log.info3("  + JSON response: {}".format(response))

    errors = get_errors(response)
    if errors:
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code <= 599:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError("Cloudflare4 JSON response failure")

    ret = {}
    for r in response['result']:
        ret[r['data']['certificate'].lower()] = r['id']

    if ret:
        return ret

    raise Except.DNSNotLive("no TLSA records found")


