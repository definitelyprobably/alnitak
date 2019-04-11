
Overview
========

The Problem
###########

If you are running a server that provides some service secured with Let's
Encrypt certificates (for example http or mail), you can naively implement
DANE quite easily: you simply need to update your DNS zone(s) by adding a
TLSA resource record (RR) that contains your X.509 certificate's association
data (typically hashed). When TLS authentication occurs, the client can now
verify that the certificate they have received is trustworthy since its
association data can be compared with the reference value in the domain's DNS
zone (typically, `DNSSEC <https://www.dnssec.net/>`_ is required to maintain
trust in the DNS replies).

However, when certificates are renewed on the server, the TLSA RR may no
longer align in accord with the certificates sent to clients by the server.
Any such client, in the absence of *any* matching TLSA RR, must then conclude
that the connection is untrustworthy and terminate the connection.

In order for DANE TLSA authentication to survive certificate renewal, two
criteria must be satisfied:

1. A new TLSA RR will need to be created when a certificate is renewed.
2. At no point during the renewal process should a user be served a certificate
   that does not match *any* TLSA RRs in the DNS zone for the domain.

Criterion 1 can be satisfied relatively easily given a programmatic way to
interact with your DNS zone(s). Criterion 2, however, will require a little
more work.

Suppose that your server offers certificate *A*, which is authenticated with
a DANE TLSA RR *a* that is currently "live" (meaning that, in theory, all DNS
queries for that RR would return *a* as a response).

If a certificate renewal occurs at time *t* so that certificate *B* is now
offered and DANE TLSA RR *b* is generated, any client connection that occurs
at times *t+dt* will erroneously offer certificate *B* to be compared to only
TLSA RR *a*, as long as the interval *dt* is less than the time it takes for
the TLSA RR *b* to be created, uploaded and to be propagated (the time it
takes for *b* to go "live"). For time intervals *dt* after certificate
renewal, all clients that wish to perform DANE authentication will
incorrectly conclude that their secure connections are untrustworthy.

::

    ---------------------------------------------------------------> time
    +++++ (A,a) ++++++++>|
                         |+++++ (B,a) ++++++>|
                                             |+++++ (B,b) +++++++++>
                         ^
                    certificate              ^
                      renewal           TLSA RR 'b'
                      A -> B         finally goes live
                         .                   .
                         .                   .
       Client auth       .    Client auth    .   Client auth
       will succeed      .     will fail     .   will succeed
                         .                   .
                         .                   .
                         t                 t + dt


The time interval *dt* cannot ever be made zero. Hence, it is not enough to
simply publish TLSA records when certificates are renewed.


For this example, let's assume this is mail, but it applies equally to anything else, like https. Typically, your service will be offered under a domain ``example.com`` and you will have configured your service to use a certificate located in ``/etc/letsencrypt/live/example.com``. The certificates in this (Let's Encrypt) "live directory" are symbolic links to the actual certificates, which are located in the "archive directory" ``/etc/letsencrypt/archive/example.com``.

If you now choose to further protect your service with DANE, you will need to create TLSA records in your DNS zone (itself secured with DNSSEC). Such a record essentially contains details of a public key certificate in your trust chain, and for 3xx TLSA records will be your endpoint certificate. Any such certificate is liable to change (more so your endpoint certificate rather than an intermediate certificate, but even these will eventually renew), which poses a few problems:

* A new TLSA record will need to be created when a certificate is renewed.
* At no point during the renewal process should a user be presented with a TLSA record that does not match to the certificate offered by the service at that point.

This last point is subtle: suppose your service is using (offers the user) a TLS certificate *A* and you have published a corresponding TLSA record *a*. If your certificate is renewed and immediately a user connects to your server, they will be offered a certificate *B* that no longer matches against your TLSA record *a*; so authentication will fail. This risk is not mitigated even if immediately after your certificate is renewed you create a new corresponding TLSA record *b*. There is still a window of opportunity for authentication to fail if a user connects in between the certificate renewal and the time it takes for the new TLSA record, *b*, to be created, uploaded to your authoritative name servers and for it to be visible to the DNS being used by the user.

The Solution
############

Since Let's Encrypt certificates are typically renewed well before they expire,
even after a certificate is renewed the previous certificates are still valid.
The solution to the above problem is therefore quite simple: continue to use
the old certificate until the TLSA records for the new certificate go "live",
and only then have your service use the new certificate.
This will work because as long as there exists one TLSA RR that matches
the certificate being offered, authentication will succeed: the existence of
other TLSA records that do not match is not taken as an authentication
failure as long as at least one record matches.

.. _HAW:

How Alnitak Works
#################

The essence of what *alnitak* does is to create symbolic links to point, at all
times, to certificates that have TLSA records that are live. Upon
initialization, *alnitak* will create a directory structure that parallels the
Let's Encrypt "live directory" ``/etc/letsencrypt/live/``::

    /etc/
    ├── letsencrypt/
    │   ├── archive/
    │   │   └── example.com/
    │   │       ├── cert1.pem
    │   │       ├── chain1.pem
    │   │       ├── fullchain1.pem
    │   │       └── privkey1.pem
    │   └── live/
    │       └── example.com/
    │           ├── cert.pem@  ->  ../../archive/example.com/cert1.pem
    │           ├── chain.pem@  ->  ../../archive/example.com/chain1.pem
    │           ├── fullchain.pem@  ->  ../../archive/example.com/fullchain1.pem
    │           └── privkey.pem@  ->  ../../archive/example.com/privkey1.pem
    │
    └── alnitak/
        └── dane/
            └── example.com/
                ├── cert.pem@  ->  ../../../letsencrypt/live/example.com/cert.pem
                ├── chain.pem@  ->  ../../../letsencrypt/live/example.com/chain.pem
                ├── fullchain.pem@  ->  ../../../letsencrypt/live/example.com/fullchain.pem
                └── privkey.pem@  ->  ../../../letsencrypt/live/example.com/privkey.pem

*Alnitak* will create an "dane directory" ``/etc/alnitak/dane/`` that will
initially contain (directories containing) certificates that are symbolic
links to certificates in the live directory ("live certificates").

Any service that reads a Let's Encrypt live certificate
``/etc/letsencrypt/live/example.com/cert.pem``, should instead
read the corresponding "dane certificate"
``/etc/alnitak/dane/example.com/cert.pem``.
Functionally, your service will behave exactly as before since the dane
certificate is a symbolic link to the live certificate::

    /etc/alnitak/dane/example.com/cert.pem  [dane cert]
        -> /etc/letsencrypt/live/example.com/cert.pem  [live cert]

and the live certificate will be a symbolic link to the actual certificate
file (this being controlled by Let's Encrypt)::

    /etc/letsencrypt/live/example.com/cert.pem  [live cert]
        -> /etc/letsencrypt/archive/example.com/cert1.pem  [archive cert]

When a certificate is renewed by Let's Encrypt, the live certificate is
changed to point to the new archive certificate::

    /etc/letsencrypt/live/example.com/cert.pem  [live cert]
           /etc/letsencrypt/archive/example.com/cert1.pem  [old archive cert]
        -> /etc/letsencrypt/archive/example.com/cert2.pem  [new archive cert]

As clarified above, this will break DANE.
*Alnitak*, when called on certbot's pre-hook, before certificate renewal is
performed, will change the dane certificates to point to the ultimate
*archive* certificate (rather than the live certificate). Then, when
certificate renewal is performed, the certificate offered by your service will
still be the old certificate::

    /etc/alnitak/dane/example.com/cert.pem  [dane cert]
        -> /etc/letsencrypt/archive/example.com/cert1.pem  [old archive cert]

When *alnitak* detects that the new live certificate's TLSA RR has gone live,
it will revert the dane certificate to point to the live certificate::

    /etc/alnitak/dane/example.com/cert.pem  [dane cert]
        -> /etc/letsencrypt/live/example.com/cert.pem  [live cert]

    /etc/letsencrypt/live/example.com/cert.pem  [live cert]
           /etc/letsencrypt/archive/example.com/cert1.pem  [old archive cert]
        -> /etc/letsencrypt/archive/example.com/cert2.pem  [new archive cert]

At this point, the complete renewal process (including DANE authentication)
will have completed, and we will be back to where we were before renewal
began, except that the certificates have been renewed.

In order to perform these checks on whether the TLSA RRs are live, and also to
create the records in the first place, *alnitak* is also designed to be able
to manage your DNS zone, either directly or by calling an external script or
program that you can provide to do this.

