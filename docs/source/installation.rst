
.. _Installation:

Installation
============

Python 3.4 or newer is required. Standard tools such as pip and/or modules to
create a virtual environment are assumed to be present.
The program's specific dependencies are:

* requests >= 2.21.0
* cryptography >= 2.4.2

Older version may also work, but have not been tested.

If your DNS records are managed by Cloudflare, then *alnitak* can use their
native API package,
`python-cloudflare <https://github.com/cloudflare/python-cloudflare>`_
in order to manage DNS records. This is not required, but is recommended;
install the package via pip as::

    ~$ pip install cloudflare

and *alnitak* will use it automatically (and fall back to requests calls
otherwise).

The program has been tested on Debian (Jessie and Stretch).
It should work for all Unix-like systems, or at least all systems that provide
fcntl, support for symbolic links and that follow the
`Filesystem Hierarchy Standard <https://wiki.linuxfoundation.org/lsb/fhs>`_).

PyPI
####

The program can be installed from `PyPI <https://pypi.org/project/alnitak/>`_
directly::

    ~$ pip install alnitak

either into a virtual environment or system-wide.

From Source
###########

Source can be downloaded from
`github <https://github.com/definitelyprobably/alnitak>`_::

    ~$ git clone https://github.com/definitelyprobably/alnitak

You can optionally create a virtual environment for the package. Once cloned,
open the newly downloaded directory and install dependencies with::

    ~/alnitak$ pip install -r requirements.txt

Installation can be done with::

    ~/alnitak$ python setup.py install

Testing
*******

The test scripts are run with pytest. First install pytest::

    ~/alnitak$ pip install pytest

You should first enter development mode before running the tests, or else
some tests will fail::

    ~/alnitak$ python setup.py develop

The tests can be run with the command::

    ~/alnitak$ python setup.py test

Note that although *alnitak* needs root permissions to run, running the
tests does not, even though the tests simulate runs of the program.
Neither do the tests require any Let's Encrypt files to be present on the
system, or interact with any such files if they are present. The tests do not
interact with the system outside the directory the tests are run from.

