
Logging
=======

By default, *alnitak* will log information to the file
``/var/log/alnitak.log`` (which can be changed via the ``--log`` flag).

The level of detail to log can be changed with the ``--log-level`` flag,
which can be given the following inputs:

* ``no``: do not log anything to the log file.
* ``normal``: minimal logging (this is the default).
* ``verbose``: more detailed logging.
* ``debug``: log even more detail.

.. warning::

  The log file *may* capture sensitive
  info at this level, although this does not include any login keys since
  they will be automatically redacted. Consider restricting permissions of
  the log file and monitoring its contents to assess this possibility.
  *Alnitak* will not change (or set) the permissions of the log file.


The following combination of flags provide a guide as to how the program will print errors and information, and where to. You will likely only ever need a few of these scenarios, but they are all listed for the sake of completion.

.. table:: Logging outcomes
    :align: center

    +-------------------+-----------------+---------+
    |       flags       |     errors      |  info   |
    +===================+=================+=========+
    |                   | logfile, stderr | logfile |
    +-------------------+-----------------+---------+
    | ``-l-``           | stderr          | stdout  |
    +-------------------+-----------------+---------+
    | ``-lno``          | stderr          |         |
    +-------------------+-----------------+---------+
    | ``-q``            | logfile         | logfile |
    +-------------------+-----------------+---------+
    | ``-l- -q``        |                 |         |
    +-------------------+-----------------+---------+
    | ``-lno -q``       |                 |         |
    +-------------------+-----------------+---------+
    | ``-Lno``          | logfile, stderr |         |
    +-------------------+-----------------+---------+
    | ``-l- -Lno``      | stderr          |         |
    +-------------------+-----------------+---------+
    | ``-lno -Lno``     | stderr          |         |
    +-------------------+-----------------+---------+
    | ``-q -Lno``       | logfile         |         |
    +-------------------+-----------------+---------+
    | ``-l- -q -Lno``   |                 |         |
    +-------------------+-----------------+---------+
    | ``-lno -q -Lno``  |                 |         |
    +-------------------+-----------------+---------+

As a general rule of thumb: by default, all messages (info or errors) are written to the logfile, with the error messages also written to stderr. If you want to write to stdout rather than to the logfile, then pass the ``-l-`` (``--log=stdout``) flag. If you want to only ever write to the logfile, then pass the ``-q`` flag. If you want to suppress all info output, pass the ``-Lno`` flag.



