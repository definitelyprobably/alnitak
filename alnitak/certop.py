
import re
from codecs import encode
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from alnitak import exceptions as Except

# Note: python 3.5+ can use X.hex() instead of encode(X,'hex').decode('ascii').
# If going to change that, then remove the 'codecs' import above.

def get_live(usage, certs):
    """Return a live certificate name from one of the prehook lines.

    Return a name (pathlib.Path) of a live certificate from one of the
    prehook lines, the appropriate certificate depending on the DANE
    record requested.

    Args:
        usage (str): not changed.
        certs (list(pathlib.Path)): not changed.

    Returns:
        pathlib.Path: taken from 'pre'. If no certificate is found an
            exception is raised.

    Raises:
        InternalError: there ought to be a prehook line for every pem cert
            in the domain folder, so there ought to be a certificate for
            whatever DANE record is requested.
    """
    if usage == '2':
        name_list = [ "chain.pem", "fullchain.pem" ]
    else:
        name_list = [ "cert.pem", "fullchain.pem" ]

    for cert in certs:
        if cert.name in name_list:
            return cert

    raise Except.InternalError("suitable cert could not be found")


def get_archive(usage, certs):
    """Return an archive certificate name from one of the prehook lines.

    Return a name (pathlib.Path) of an archive certificate from one of
    the prehook lines, the appropriate certificate depending on the DANE
    record requested.

    Args:
        usage (str): not changed.
        certs (list(pathlib.Path)): not changed.

    Returns:
        pathlib.Path: taken from 'pre'. If no certificate is found an
            exception is raised.

    Raises:
        InternalError: there ought to be a prehook line for every pem cert
            in the domain folder, so there ought to be a certificate for
            whatever DANE record is requested.
    """
    if usage == '2':
        name_regex = r"(full)?chain[0-9]+\.pem"
    else:
        name_regex = r"(cert|fullchain)[0-9]+\.pem"

    for cert in certs:
        if re.match(name_regex, cert.name):
            return cert

    raise Except.InternalError("suitable cert could not be found")


def get_xive(usage, certs):
    """Return a live/archive certificate name from one of the prehook lines.

    Return a name (pathlib.Path) of either an archive or live certificate
    from one of the prehook lines, the appropriate certificate depending on
    the DANE record requested.

    Args:
        usage (str): not changed.
        certs (list(pathlib.Path)): not changed.

    Returns:
        pathlib.Path: taken from 'pre'. If no certificate is found an
            exception is raised.

    Raises:
        InternalError: there ought to be a prehook line for every pem cert
            in the domain folder, so there ought to be a certificate for
            whatever DANE record is requested.
    """
    if usage == '2':
        name_regex = r"(full)?chain[0-9]*\.pem"
    else:
        name_regex = r"(cert|fullchain)[0-9]*\.pem"

    for cert in certs:
        if re.match(name_regex, cert.name):
            return cert

    raise Except.InternalError("suitable cert could not be found")


def read_cert(cert, tlsa_usage):
    """Return the PEM-encoded content of a certificate file.

    Open a certificate file and return a str that is the PEM-encoded
    public key info in that file, in the case of a fullchain file, only
    the necessary key is returned, depending on the DANE record requested.

    Args:
        cert (pathlib.Path): PEM-encoded file to read.
        tlsa_usage (str): tlsa usage field

    Returns:
        str: PEM-encoded content of 'cert' (with BEGIN and END headers and
            footers). If 'cert' is a fullchain file, the relevent
            certificate PEM is extracted.

    Raises:
        DNSProcessingError: if 'cert' could not be opened or no appropriate
            PEM section in a fullchain file could be found. Also returned
            if there is no content of the 'cert' file.
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

        if tlsa_usage == '2':
            if len(pems) < 2:
                raise Except.DNSProcessingError("creating hash: '{}' file: no intermediate certificate found".format(cert))
            cert_data = pems[1]
        else:
            if len(pems) < 1:
                raise Except.DNSProcessingError(
                    "creating hash: '{}' file: no certificate found".format(
                                                                        cert))
            cert_data = pems[0]

    if len(cert_data) == 0:
        raise Except.DNSProcessingError(
                "creating hash: '{}' file: no data found".format(cert))

    return cert_data

def get_hash(selector, matching, data):
    """Create a DANE record 'certificate data' (hash) string.

    Given a certificate PEM-encoded public key, generate 'certificate data'
    (which we otherwise call a 'hash') for the DANE record.

    Args:
        selector (str): TLSA selector field (0|1).
        matching (str): TLSA matching-type field (0|1|2).
        data (str): PEM-encoded public key data.

    Returns:
        str: the 'certificate data' (hash).

    Raises:
        InternalError: if generating the 'certificate data' fails for any
            reason.
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



