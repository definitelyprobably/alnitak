
.. _Running:

Running
=======

*Alnitak* can be run in several modes, each of which define a particular
behaviour. These modes are invoked as::

    ~$ alnitak [mode] [options...]

The mode must be the first argument to the program and may be followed by
flags and/or arguments specific to that mode. If no mode is given, then
the program runs in default mode.

Modes
#####

default
*******

After certificates have been renewed, any new DNS record that has been
published must be allowed time to propogate before the dane certificate 
symlink is reverted to pointing to the new live certificate. In default
mode the program checks to see if the new DNS record has gone live, and if
so performs this last step. With no certificates to process, running the
program in default mode will do nothing.

pre
***

The program will move the dane certificate symlinks to point to archive
certificates, in preparation for a possible certificate renewal. This mode
is indended to be run before a certificate renewal is performed, preferably
on certbot's pre-hook. The synonym ``prehook`` is also provided for this
mode.

deploy
******

To be run after certificate renewal has taken place, the program will move
the dane certificate symlinks back to pointing to live certificates for all
certificates that were not renewed. For certificates that were renewed, a
TLSA record is published for the new live certificate.
The synonyms ``deployhook``, ``post`` and ``posthook`` are also provided
for this mode.

reset
*****

In this mode the program will recreate the dane directory
(``/etc/alnitak/dane/``). This effectively means that all dane certificate
symlinks will to point back to live certificates. This is the meaning of
'resetting' the dane directory.

init
****

A synonym for the ``reset`` mode. This mode wil create and populate the
dane directory.

configtest
**********

Test the configuration file for syntax errors, or targets that cannot be
located (i.e., certificates that cannot be found).

print
*****

Print TLSA certificate data (usually, hashes) that form the data fields of
the TLSA record(s).
With no arguments, it will print certificate data for all TLSA specifications
indicated in the configuration file. Otherwise, required outputs can be
specified by listing them as arguments to the program as follows::

    ~$ alnitak print 311:/path/to/cert 201:path/to/cert

which will print::

    - 3 1 1 123456789abcdef0... /path/to/cert
    - 2 0 1 fedcba9876543210... /cwd/path/to/cert

The arguments must be formatted as ``XYZ:CERT``, where ``XYZ`` are the
concatenated TLSA parameters, and ``CERT`` is the file to extract data from.    

When dealing with certificates in the Let's Encrypt directory
(``/etc/letsencrypt``), the output will be slightly different::

    ~$ alnitak print 311:/etc/letsencrypt/live/example.com/cert.pem

will print::

    example.com 3 1 1 123456789abcdef0... /etc/letsencrypt/live/example.com/cert.pem

where the first field is not ``-``, but instead the domain directory the
certificate is in (here, ``example.com``).

With Let's Encrypt certificates, you also do not need to specify the
exact file, but can just give the domain folder name::

    ~$ alnitak print 311:example.com

which will print::

    example.com 3 1 1 123456789abcdef0... /etc/letsencrypt/live/example.com/cert.pem

This is the certificate data for the relevant file in the live directory.
If you want to print certificate data for all the archive certificates,
then you can specify that the archive directory certificates are intended
as follows::

    ~$ alnitak print 302:archive/example.com

which will print::

    example.com 3 0 2 123456789abcdef0... /etc/letsencrypt/archive/example.com/cert1.pem
    example.com 3 0 2 23456789abcdef01... /etc/letsencrypt/archive/example.com/cert2.pem
    example.com 3 0 2 3456789abcdef012... /etc/letsencrypt/archive/example.com/cert3.pem
    ...


Flags
#####

The program accepts the following flags. Not every flag is available in
every mode. Pass::

    ~$ alnitak [mode] --help

to see which flags are accepted by which mode.


configuration file
******************

::

    -c CONFIG, --config CONFIG

Will read the configuration specified instead of the default
``/etc/alnitak.conf``.

letsencrypt directory
*********************

::

    -C DIR, --letsencrypt-directory DIR

Will set the directory the Let's Encrypt live and archive certificate
directories are to be located in to ``DIR`` instead of the default
``/etc/letsencrypt/``. This can also be set in the configuration file
itself via the command::

    letsencrpyt_directory = DIR

dane directory
**************

::

    -D DIR, --dane-directory DIR

Will set the directory the dane certificates are to be found in
to be ``DIR`` instead of the default ``/etc/alnitak/dane``. You may set
this to any value you wish, as long as you are consistent, but the
default value will normally suffice. This can also be set in the
configuration file itself via the command::

    dane_directory = DIR

log file
********

::

    -l LOG, --log LOG

Output to log file ``LOG`` instead of the default ``/var/log/alnitak.log``.
If ``LOG`` is a directory, it will log to ``LOG/alnitak.log``.
If ``LOG`` is given the value ``-`` or ``stdout``, then output
to stdout instead of to a log file. If ``LOG`` is given the value ``no``,
then disable logging. (To use any of these special values as literal file
names, give them as relative paths; e.g. ``./stdout``.) See :ref:`Logging`
for more details.

log level
*********

::

    -L LEVEL, --level LEVEL

Set the level of logging to be performed. The allowed values are ``no``,
``normal`` (the default value), ``verbose`` and ``debug``. See :ref:`Logging`
for more details.

ttl
***

::

    -t SEC, --ttl SEC

Set the time-to-live value to ``SEC`` seconds.
The time-to-live value is the maximum time before which no switch to using
the renewed certificate is allowed after the TLSA record for the new
certificate has been published. In effect, this is the minumum time
allotted for the new DNS record to be allowed to propogate before we switch
to using the new certificate. The default value of 86400 seconds (1 day)
is quite conservative, but should not cause any problems. The danger with
setting too low a value is the risk in offering a certificate for which
the user's DNS responses do not serve the new TLSA record, and so DANE
authentication will fail. Regardless, any value between 0 and 604800
(7 days), inclusive, is allowed.

quiet
*****

::

    -q, --quiet

Do not print any output to stdout or stderr. Error messages from command-line
errors are not included: they will always be printed to stderr.


Exit Codes
##########

The program will exit with the following codes:

* 0: program executed without errors.
* 1: program encountered errors during execution.
* 2: command-line errors.
* 3: syntax errors in the configuration file.
* 4: error in creating a lock file: program aborted.
* 15: another instance of the program is already running.

If there has been a problem in writing output (e.g. to the logfile),
the exit codes above will be increased in value by 16.

