
import re
from codecs import encode
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from alnitak import exceptions as Except

# Note: python 3.5+ can use X.hex() instead of encode(X,'hex').decode('ascii').
# If going to change that, then remove the import above.

def get_live(tlsa, pre):
    """
    Calls:
        - None

    Exceptions:
        - Except.InternalError
    """
    if tlsa.usage == '2':
        name_list = [ "chain.pem", "fullchain.pem" ]
    else:
        name_list = [ "cert.pem", "fullchain.pem" ]

    for cert in [ l.cert.live for l in pre ]:
        if cert.name in name_list:
            return cert

    raise Except.InternalError("suitable cert could not be found")

def get_archive(tlsa, pre):
    """
    Calls:
        - None

    Exceptions:
        - Except.InternalError
    """
    if tlsa.usage == '2':
        name_regex = r"(full)?chain[0-9]+\.pem"
    else:
        name_regex = r"(cert|fullchain)[0-9]+\.pem"

    for l in pre:
        if re.match(name_regex, l.cert.archive.name):
            return l.cert.archive

    raise Except.InternalError("suitable cert could not be found")

def read_cert(cert):
    """
    Calls:
        - None

    Exceptions:
        - Except.DNSProcessingError
    """
    try:
        with open(str(cert), "r") as file:
            cert_data = file.read()
    except FileNotFoundError as ex:
        raise Except.DNSProcessingError(
                "creating hash: certificate file '{}' not found".format(
                                                                ex.filename))
    except OSError as ex:
        raise Except.DNSProcessingError(
                "creating hash: certificate file '{}': {}".format(
                                        ex.filename, ex.strerror.lower()))

    if re.match(r"fullchain[0-9]*\.pem$", cert.name):
        pems = []
        temp = ""
        for l in cert_data.splitlines():
            if l == "-----BEGIN CERTIFICATE-----":
                if temp:
                    pems += [ temp ]
                temp = l
            else:
                temp += "\n{}".format(l)
        if temp:
            pems += [ temp ]

        if tlsa.usage == '2':
            if len(pems) < 2:
                raise Except.DNSProcessingError("creating hash: '{}' file: no intermediate certificate found".format(cert))
            cert_data = pems[1]
        else:
            if len(pems) < 1:
                raise Except.DNSProcessingError(
                    "creating hash: '{}' file: no certificate found".format(
                                                                        cert))
            cert_data = pems[0]

    return cert_data

def get_hash(selector, matching, data):
    """
    Calls:
        - None

    Exceptions:
        - Except.DNSProcessingError
    """
    cert = x509.load_pem_x509_certificate(
                                    bytes(data, 'utf-8'), default_backend())

    try:
        if selector == '0':
            # use the full certificate
            if matching == '0':
                return encode(cert.public_bytes(
                                    encoding=serialization.Encoding.DER),
                                    'hex').decode('ascii')
            elif matching == '1':
                return encode(cert.fingerprint(hashes.SHA256()),
                              'hex').decode('ascii')
            else:
                return encode(cert.fingerprint(hashes.SHA512()),
                              'hex').decode('ascii')
        else:
            # use the public key
            der = cert.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
            if matching == '0':
                return encode(der, 'hex').decode('ascii')
            elif matching == '1':
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(der)
                return encode(digest.finalize(), 'hex').decode('ascii')
            else:
                digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
                digest.update(der)
                return encode(digest.finalize(), 'hex').decode('ascii')
    except cryptography.exceptions.UnsupportedAlgorithm:
        raise Except.InternalError("unsupported hash algorithm")
    except TypeError:
        raise Except.InternalError("certificate data not a byte string")



