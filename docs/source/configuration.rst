
Configuration
=============

Once installed, *alnitak* must be configured to work properly.
Configuration is performed by editing the file ``/etc/alnitak.conf``.

Alnitak
#######

*Alnitak* needs to know:

1. What TLSA records to create when a domain's certificates are renewed.
2. How to interact with your domain's DNS zone(s).

This information is passed to *alnitak* via the creation of `Targets`_ and
`API Schemes`_ respectively in the configuration file.

Targets
*******

A "target" is an instruction on what TLSA records to create when a domain's
certificates are renewed. A target looks like this::

    [example.com]
    tlsa = 311 443 tcp

With this target in the configuration file, if a certificate in
``/etc/letsencrypt/archive/example.com/`` is renewed, *alnitak* will attempt
to create a TLSA RR::

    TLSA 3 1 1 _443._tcp.example.com

A target is constructed from the domain directory name that the Let's Encrypt
certificates are located in as a section header::

    [DOMAIN]
    # ...

(which indicates that the creation of TLSA RRs will triggered when
certificates in ``/etc/letsencrypt/live/DOMAIN/`` are renewed), and at least
one ``tlsa`` parameter::

    tlsa = PARAMS PORT [PROTOCOL] [RR_DOMAIN]

A ``tlsa`` parameter requires the concatenated parameters of the TLSA record
(the usage field, the selector field and the matching type field in that
order), the port the service is running on, and optionally an explicit
protocol for the service and the domain to appear in the record.
If no protocol is explicitly specified, "tcp" is assumed; and if no domain is
explicitly specified, the target's domain is used.

Note that only usage fields '2' (DANE-TA) and '3' (DANE-EE) are supported.
Selector field inputs '0' and '1' are both supported, as well as the matching
type fields '0', '1' and '2'. Hence, ``PARAMS`` can take any of the following
values: "[23][01][012]".

Examples
++++++++

Example 1
---------

Target::

    [example.com]
    tlsa = 311 25 smtp.example.com

will trigger the TLSA record::

    TLSA 3 1 1 _25._tcp.smtp.example.com

to be created when certificates in ``/etc/letsencrypt/archive/example.com``
are renewed.

Example 2
---------

Target::

    [example.com]
    tlsa = 312 443
    tlsa = 300 8443 udp
    tlsa = 211 443 tcp www.example.com

will trigger the TLSA records::

    TLSA 3 1 2 _443.tcp.example.com
    TLSA 3 0 0 _8443.udp.example.com
    TLSA 2 1 1 _443.tcp.www.example.com

to be created when certificates in ``/etc/letsencrypt/archive/example.com``
are renewed.


API Schemes
***********

An API scheme tells *alnitak* how it should interact with your domain's DNS
zone(s). If your DNS is managed by Cloudflare, then *alnitak* can interact
with Cloudflare directly in order to create/delete DNS TLSA records. If you
manage your zone(s) locally or via another provider, then the ``exec`` API
scheme is provided, whereby *alnitak* can call an external program to perform
the relevent DNS operations.

An API scheme is specified with an ``api`` parameter like so::

    api = SCHEME [inputs...]

and can either be placed within a target::

    # target 1
    [example.com]
    tlsa = ...
    api = SCHEME [inputs...]

    # target 2
    [example.org]
    tlsa = ...
    api = SCHEME [inputs...]

in which case the API schemes specified will apply to only that particular
target; or else can appear outside of all targets::

    api = SCHEME [inputs...]

    # target
    [example.com]
    tlsa = ...

    # target
    [example.org]
    tlsa = ...

in which case the API scheme will apply to all targets for which no API scheme
is explicitly given in the target.

Where both an API scheme outside of all targets and a target-specific API
scheme exists, only the target-specific API scheme will apply to the target in
question.

Multiple API schemes cannot apply to any specific target. Where more than one
``api`` parameter is given in a given context, only the last such occurring one
will be in effect. That is, for the following::

    api = SCHEME_1
    api = SCHEME_2

    [target1]
    tlsa = ...

    [target2]
    tlsa = ...
    api = SCHEME_3
    api = SCHEME_4

target ``target1`` will have API scheme ``SCHEME_2`` and target ``target2``
will have API scheme ``SCHEME_4``.


Exec API Scheme
+++++++++++++++

The ``exec`` API scheme is specified like so::

    api = exec PROG [ARGS...]

which will call ``PROG ARGS...`` as needed to create/delete DNS records.

The external program must be able to create and delete DANE TLSA records,
and should distinguish between these two operations by reading the
environment for a parameter called ``TLSA_OPERATION``, which will be set
to the value "publish" or "delete" respectively.

.. note::

   Any flags specified in the API scheme will be passed equally to both
   operations. The two operations of publishing and deleting DNS records
   should be distinguished only by reading the environment parameter
   ``TLSA_OPERATION``.

Under either operation, the environment will contain:

* ``PATH``: set to ``"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"``
* ``IFS``: set to ``" \t\n"``
* ``TLSA_USAGE``: set to the usage field of the TLSA record.
* ``TLSA_SELECTOR``: set to the selector field of the TLSA record.
* ``TLSA_MATCHING``: set to the matching type field of the TLSA record.
* ``TLSA_PARAM``: set to a string formed by concatenating the usage, selector and matching type fields.
* ``TLSA_PORT``: set to the TLSA record port.
* ``TLSA_PROTOCOL``: set to the TLSA record protocol.
* ``TLSA_DOMAIN``: set to the TLSA record domain.
* ``TLSA_HASH``: set to the TLSA record's certificate association data.

Creating records
----------------

In addition to the environment parameters above, the following will be set:

* ``TLSA_OPERATION``: set to ``"publish"``

The program ought to create a DANE TLSA record with certificate association
data as contained in the parameter ``TLSA_HASH``.

When done, the program must exit with code:

* 0     -  if the TLSA record was published successfully.
* 1     -  if the TLSA record is already up.
* 2+    -  if an error occurred that should cause *alnitak* to exit with an
  error code.
* 128+  -  if an error occurred that should not cause *alnitak* to exit with
  an error code.

Deleting records
----------------

In addition to the environment parameters above, the following will be set:

* ``TLSA_OPERATION``: set to ``"delete"``
* ``TLSA_LIVE_HASH``: may be present, and if so, will be set to the
  certificate association data of the new TLSA record that was previously
  published.

The program ought to delete a DANE TLSA record with certificate association
data as contained in the parameter ``TLSA_HASH``. If the parameter
``TLSA_LIVE_HASH`` is set, the program ought only to do such a deletion if a
DANE TLSA record with certificate association data given by the value of
``TLSA_LIVE_HASH`` is live.

When done, the program must exit with code:

* 0     - if the old record was deleted successfully.
* 1     - if the new record was not up yet, so the old one was not yet deleted.
* 2+    - if an error occurred that should cause *alnitak* to exit with an
  error code.
* 128+  - if an error occurred that should not cause *alnitak* to exit with
  an error code.

Example Code
------------

Here is an outline of some basic bash shell code that will help illustrate
the above requirements::

    #!/bin/bash
    #
    # api_get()    - check if a DNS record is live
    # api_post()   - publish a DNS record
    # api_delete() - delete a DNS record


    # set 'json' to the json data of the record we will be processing:
    read -d = json <<EOF
    { "tlsa": "_$TLSA_PORT._$TLSA_PROTOCOL._$TLSA_DOMAIN",
      "data": {
        "usage": $TLSA_USAGE,
        "selector": $TLSA_SELECTOR,
        "matching_type": $TLSA_MATCHING
        "certificate_data": "$TLSA_HASH"
        }
    }
    =
    EOF

    # set 'json_new' for when 'TLSA_LIVE_HASH' is set. If not set we
    # won't use this anyway
    read -d = json_new <<EOF
    { "tlsa": "_$TLSA_PORT._$TLSA_PROTOCOL._$TLSA_DOMAIN",
      "data": {
        "usage": $TLSA_USAGE,
        "selector": $TLSA_SELECTOR,
        "matching_type": $TLSA_MATCHING
        "certificate_data": "$TLSA_LIVE_HASH"
        }
    }
    =
    EOF


    # delete a TLSA record
    if [[ "$TLSA_OPERATION" == "delete" ]]; then

        # if 'TLSA_LIVE_HASH' is set, we must first check if that
        # record is live before we can delete anything:
        if [[ -z "$TLSA_LIVE_HASH" ]]; then
            # 'TLSA_LIVE_HASH' not set; unconditionally delete the
            # old TLSA record:
            if api_delete "$json"; then
                exit 0
            else
                exit 2
            fi
        else
            # first we need to check if the new TLSA record is up:
            if api_get "$json_new"; then
                # new TLSA record is up; we can delete the old one...
                if api_delete "$json"; then
                    exit 0
                else
                    exit 2
                fi
            else
                # new TLSA not yet up; we cannot delete the old
                # one yet...
                exit 1
            fi
        fi

    # publish a TLSA record
    else
        # check if record is already up:
        if api_get "$json"; then
            # record is already up
            exit 1
        else
            # record not already up
            if api_post "$json"; then
                exit 0
            else
                exit 2
            fi
        fi
    fi


Cloudflare API Scheme
+++++++++++++++++++++

The ``cloudflare`` API scheme is specified either like::

    api = cloudlfare email:EMAIL zone:ZONE key:KEY

where ``EMAIL``, ``ZONE`` and ``KEY`` are the credentials required to use
Cloudflare's API; or::

    api = cloudflare FILE

where ``FILE`` is the location of the file that contains the credentials.
Where a credentials file is given, it should contain::

    # comments are allowed
    email=EMAIL  # comments allowed here too
    zone = ZONE  # whitespace is allowed...
     key =KEY    # ...except for newlines

It is recommended to use a credentials file rather than placing the
credentials directly in the configuration file.
The credentials file should also be appropriately secured against arbitrary
access. *Alnitak* needs root permissions to operate, and will open the file
as root, so as restrictive a set of permissions as operationally necessary
should be considered. At least the file should not be world readable or
writable.

.. note::

   The format for the credentials file here differs than that for the
   credentials file used by certbot if using the cloudflare dns plugin.
   Currently, you cannot use the latter for the former.


Certbot
#######

*Alnitak* is designed to run on certbot's pre-hook and deploy-hook in order
to ensure that certificates being used by a service do not break DANE
authentication (see :ref:`HAW` for more details).
As such, whenever *alnitak* is being used to manage DANE TLSA records, all
certbot renewals **must** call *alnitak* on these hooks in order for DANE to
continue working.

When running certbot explicitly, simply ensure the hooks are specified::

    $ certbot renew --pre-hook "alnitak --pre" --deploy-hook "alnitak --deploy" ...

You must run ``alnitak --pre`` on the certbot pre-hook and ``alnitak --deploy``
on the certbot deploy-hook. Other alnitak flags may also be given, but these
**must** be specified.

The command ``alnitak --pre ...`` ensures that dane certificates are prepared
for a potential certificate renewal (amongst other things). Likewise, the
command ``alnitak --deploy`` ensures that dane certificates are either
restored if no renewal occurs, or creates DANE TLSA records otherwise.

When certificate renewal is automated, either as a cron job or systemd timer,
the hooks must be set in the Let's Encrypt renewal configuration files (in the
directory ``/etc/letsencrypt/renewal``); the following lines must be added to
the ``renewalparams`` section::

    [renewalparams]
    pre_hook = alnitak --pre
    renew_hook = alnitak --deploy

These changes must be made to all such renewal configuration files for which
you wish *alnitak* to manage DANE TLSA records. Again, additional commands to
the *alnitak* program may also be specified, but ``--pre`` and ``--deploy``
**must** at least be present, as shown.

Technically, ``alnitak --pre`` needs to be run before certbot renewal occurs,
and ``alnitak --deploy`` needs to be run after certbot renewal occurs and be
given a list of domains that were renewed in the environment parameter
``RENEWED_DOMAINS`` (space or tab delimited).
The most convenient way to do this is on the certbot pre and deploy hooks.

.. warning::

   Do not run ``alnitak --deploy`` on certbot's post hook. *Alnitak* needs to
   know which domains were renewed, and the environment parameter
   ``RENEWED_DOMAINS`` is not set on the post hook; it is only set on the
   deploy hook.
   Older versions of certbot may be in conflict with this prescription.
   Ensure that ``alnitak --deploy`` runs on whichever hook sets
   ``RENEWED_DOMAINS`` and things will work fine.


System
######

In addition to running on certbot's pre and deploy hooks whenever a
certificate renewal occurs, *alnitak* also needs to run periodically on the
system so that any certificates that were being held back until the new
certificates' DANE TLSA records go live will be switched to the new ones when
they do. Here, you simply need to run *alnitak* (without any special flags)
however often you like. For example, as a cron job every day at 1am and 1pm::

    # crontab
    PATH = /usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
    #
    # m h  dom mon dow   command
    0   1  *   *   *     alnitak
    0   13 *   *   *     alnitak

The times chosen to run at can be anything that is convenient: when
*alnitak* is called, it will check if the DNS records are live only after a
set period of time has elapsed in order to allow the changes to the zone to
propagate. By default this time is set to 24 hours, but can be adjusted with
the ``--ttl`` flag.


