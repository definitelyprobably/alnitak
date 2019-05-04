
Quickstart
==========

First, install with pip as usual (see :ref:`Installation`)::

    ~$ pip install alnitak

Next, create a configuration file ``/etc/alnitak.conf`` containing details
of the certificates you wish to generate DANE TLSA records for. See
:ref:`Configuration` for more details.

Then initialize alnitak in order to create and populate the
``/etc/alnitak/dane`` directory::

    ~$ alnitak init

Finally, run *alnitak* daily, for example as a cron job::

    # m h  dom mon dow   command
    0 3,15 *   *   *     /usr/bin/alnitak

and also add it to certbot's pre- and deploy-hooks::

    [renewalparams]
    pre_hook = alnitak pre
    renew_hook = alnitak deploy

(See :ref:`ConfCertbot` for more details.)

Now alnitak is ready to be used. All services that use certificates that
you wish to publish TLSA records for should use certificates
``/etc/alnitak/dane/example.com/cert.pem`` instead of directly using the
Let's Encrypt certificate ``/etc/letsencrypt/live/example.com/cert.pem``
(and analogously for the other certificate files).

Certificate renewal will now also automatically renew DANE TLSA
records, and needs no manual intervention.

