
Alnitak documentation
=====================

This is the documentation for *alnitak*, a program designed to help with
managing `DANE TLSA <https://tools.ietf.org/html/rfc6698>`_ records for
systems that use `Let's Encrypt <https://letsencrypt.org/>`_ certificates.

This program is designed to automate the updating (and deleting) of DNS
TLSA records when Let's Encrypt certificates are renewed.


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   overview
   installation
   configuration
   running
   logging


Status
######

The code is in beta. The program is functional, but more testing is required.
If you wish to use the program, then you will likely find that the program
works, but *may* be temperamental to changes in your setup. Thus, it is
recommended that you check that everything works by forcing a certificate
renewal, if you can, and to also keep a check on automated renewals, if
error reporting mechanisms are not already in place.
