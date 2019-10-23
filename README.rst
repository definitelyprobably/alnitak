
=========
 Alnitak
=========

This branch is the development branch for version 0.3.

This program is designed to help manage `DANE (TLSA) <https://tools.ietf.org/html/rfc6698>`_ records on a server using `Let's Encrypt <https://letsencrypt.org/>`_ certificates. Specifically, if you are thinking of using DANE to secure a service encrypted with Let's Encrypt certificates, you will at least need a reliable way to update your DNS TLSA records when your TLS certificates are renewed. This program can help you do this.

Documentation is provided at https://alnitak.readthedocs.io/en/latest/.

.. image:: https://readthedocs.org/projects/alnitak/badge/?version=latest
    :target: https://alnitak.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://travis-ci.org/definitelyprobably/alnitak.svg?branch=devel-0.3
    :target: https://travis-ci.org/definitelyprobably/alnitak

.. image:: https://codecov.io/gh/definitelyprobably/alnitak/branch/devel-0.3/graph/badge.svg
  :target: https://codecov.io/gh/definitelyprobably/alnitak


Status
======

- [X] core backend operations
- [ ] backend: printing records
- [ ] backend: editing state file
- [ ] backend: editing config file
- [ ] frontend operations: command-line parser
- [ ] frontend operations: config file
- [ ] frontend operations: state file
- [ ] logging


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
