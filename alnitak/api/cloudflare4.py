
import requests

from alnitak import exceptions as Except


def delete(prog, api, tlsa, id):
    """
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

    errors = "\n".join(response['errors'])
    if errors:
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code <= 599:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError("Cloudflare4 JSON response failure")



def publish(prog, api, tlsa, hash):
    """
    Calls:
    Exceptions:
        - Except.DNSNotLive
            if DNS couldn't be published, but there was no actual internal
            command errors
        - Except.DNSProcessingError
            if the command failed for some reason
        - Except.DNSSkipProcessing
            if the record is already up
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

    errors = "\n".join([ "{}: {}".format(a['code'], a['message'])
                                                for a in response['errors'] ])
    if errors:
        if response['errors'][0]['code'] == 81057:
            # we will only accept this code if it is the only error
            # encountered
            raise Except.DNSSkipProcessing(response['errors'][0]['message'])
        raise Except.DNSProcessingError(errors)

    if r.status_code >= 400 and r.status_code <= 599:
        raise Except.DNSProcessingError(
                "Cloudflare4 HTTP response was {}".format(r.status_code))

    if not response['success']:
        raise Except.DNSProcessingError("Cloudflare4 JSON response failure")



def read(prog, api, tlsa):
    """
    Returns:
        - a dictionary of { "hash": "id", ... }
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

    errors = "\n".join(response['errors'])
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


