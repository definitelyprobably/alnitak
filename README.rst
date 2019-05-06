
=========
 Alnitak
=========

This program is designed to help manage `DANE (TLSA) <https://tools.ietf.org/html/rfc6698>`_ records on a server using `Let's Encrypt <https://letsencrypt.org/>`_ certificates. Specifically, if you are thinking of using DANE to secure a service encrypted with Let's Encrypt certificates, you will at least need a reliable way to update your DNS TLSA records when your TLS certificates are renewed. This program can help you do this.


Documentation is provided at https://alnitak.readthedocs.io/en/latest/.

.. image:: https://readthedocs.org/projects/alnitak/badge/?version=latest
    :target: https://alnitak.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://travis-ci.org/definitelyprobably/alnitak.svg?branch=master
    :target: https://travis-ci.org/definitelyprobably/alnitak

.. image:: https://codecov.io/gh/definitelyprobably/alnitak/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/definitelyprobably/alnitak


Status
======

Code is in beta. Program is functional, but more testing is required.
If you wish to use the program, then you will likely find that the program
works, but *may* be temperamental to changes in your setup. Thus, it is
recommended that you check that everything works by forcing a certificate
renewal, if you can, and to also keep a check on automated renewals, if no
error reporting mechanisms are not already in place.


Licence
=======

MIT License

Copyright (c) 2019 K. S. Kooner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
