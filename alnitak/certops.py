
from codecs import encode
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from alnitak import exception

# Note: python 3.5+ can use X.hex() instead of encode(X,'hex').decode('ascii').
# If going to change that, then remove the 'codecs' import above.

def get_pem(state, domain, spec, use_renew = False):
    '''
    '''
    target = state.targets[domain]
    params = target['records'][spec]['params']
    usage = params['usage']

    # Note: candidate_certs is a dict where the keys are the certificates
    # to attempt to read, and the associated value is the index value of the
    # PEM block to be used.
    # For example, for DANE-EE(3), we take the first (only) PEM block
    # in 'cert.pem' or else the first PEM block in 'fullchain.pem', so these
    # keys both have value '0'; however, for DANE-TA(2) we take the first
    # (only) PEM block in 'chain.pem' or else the second PEM block in
    # 'fullchain.pem', so these keys have value '0' and '1' respectively.
    if str(usage) in ['1', '3']:
        if use_renew:
            candidate_certs = { target['certs']['cert.pem']['renew']: 0,
                                target['certs']['fullchain.pem']['renew']: 0 }
        else:
            candidate_certs = { target['certs']['cert.pem']['archive']: 0,
                                target['certs']['fullchain.pem']['archive']: 0 }
    else:
        if use_renew:
            candidate_certs = { target['certs']['chain.pem']['renew']: 0,
                                target['certs']['fullchain.pem']['renew']: 1 }
        else:
            candidate_certs = { target['certs']['chain.pem']['archive']: 0,
                                target['certs']['fullchain.pem']['archive']: 1 }

    for cert in candidate_certs:
        try:
            with open(str(cert), 'r') as file:
                cert_content = file.read().splitlines()

            pems = split_pem_data(cert_content)

            return pems[ candidate_certs[cert] ]

        except OSError as ex:
            # add the error as a warning since this _may_ not be fatal
            if state.handler:
                state.handler.warning( Error(2000, "certificate '{}': {}".format(
                        ex.filename, ex.strerror ) ))
            continue
        except IndexError:
            # add the error as a warning since this _may_ not be fatal
            if state.handler:
                state.handler.warning( Error(2001, "certificate '{}': expected PEM data headers missing".format(cert)) )
            continue

    # if we hit this point, errors in all the candidate files have been found
    raise exception.AlnitakError( Error(2010, "record '{}': no usable certificate found".format(state.tlsa_record_formatted(domain, spec)) ) )

def split_pem_data(data):
    '''
    '''
    pems = []
    buf = ''
    for l in data:
        if l == '-----BEGIN CERTIFICATE-----':
            # if buffer is not empty, then flush its contents into 'pems'
            if buf:
                pems += [ buf ]
            # and start a new buffer
            buf = l
        else:
            # add line to the buffer
            buf += '\n{}'.format(l)

    # add any remaining content of the buffer into 'pems'
    if buf:
        pems += [ buf ]

    return pems

def get_cert_data(state, domain, spec, pem):
    '''
    '''
    params = state.targets[domain]['records'][spec]['params']
    usage = params['usage']
    selector = params['selector']
    matching_type = params['matching_type']
    try:
        cert = x509.load_pem_x509_certificate(
                                    bytes(pem, 'utf-8'), default_backend())

    # if the PEM data is malformed a ValueError exception will be raised
    # with message 'Unable to load certificate'. We'll give a more descriptive
    # error message.
    except ValueError:
        raise exception.AlnitakError( Error(2010, "record '{}': creating certificate data failed: malformed PEM data".format(state.tlsa_record_formatted(domain, spec)) ))

    if selector == '0':
        # use the full certificate
        if matching_type == '0':
            return encode(cert.public_bytes(
                                encoding=serialization.Encoding.DER),
                                'hex').decode('ascii')
        elif matching_type == '1':
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
        if matching_type == '0':
            return encode(der, 'hex').decode('ascii')
        elif matching_type == '1':
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(der)
            return encode(digest.finalize(), 'hex').decode('ascii')
        else:
            digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
            digest.update(der)
            return encode(digest.finalize(), 'hex').decode('ascii')

