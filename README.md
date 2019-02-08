# Alnitak

This program is designed to help manage [DANE (TLSA)](https://tools.ietf.org/html/rfc6698) records on a server using [Let's Encrypt](https://letsencrypt.org/) certificates. Specifically, if you are thinking of using DANE to secure a service encrypted with Let's Encrypt certificates, you will at least need a reliable way to update your DNS TLSA records when your TLS certificates are renewed. This program can help you do this.

## The Problem

Suppose you are running a server that provides some service secured with Let's Encrypt certificates. For this example, let's assume this is mail, but it applies equally to anything else, like https. Typically, your service will be offered under a domain `example.com` and you will have configured your service to use a certificate located in `/etc/letsencrypt/live/example.com`. The certificates in this (Let's Encrypt) "live directory" are symbolic links to the actual certificates, which are located in the "archive directory" `/etc/letsencrypt/archive/example.com`.

If you now choose to further protect your service with DANE, you will need to create TLSA records in your DNS zone (itself secured with DNSSEC). Such a record essentially contains details of a public key certificate in your trust chain, and for 3xx TLSA records will be your endpoint certificate. Any such certificate is liable to change (more so your endpoint certificate rather than an intermediate certificate, but even these will eventually renew), which poses a few problems:

* A new TLSA record will need to be created when a certificate is renewed.
* At no point during the renewal process should a user be presented with a TLSA record that does not match to the certificate offered by the service at that point.

This last point is subtle: suppose your service is using (offers the user) a TLS certificate *A* and you have published a corresponding TLSA record *a*. If your certificate is renewed and immediately a user connects to your server, they will be offered a certificate *B* that no longer matches against your TLSA record *a*; so authentication will fail. This risk is not mitigated even if immediately after your certificate is renewed you create a new corresponding TLSA record *b*. There is still a window of opportunity for authentication to fail if a user connects in between the certificate renewal and the time it takes for the new TLSA record, *b*, to be created, uploaded to your authoritative name servers and for it to be visible to the DNS being used by the user.

## The Solution

Since Let's Encrypt certificates are typically renewed well before they expire, even after a certificate is renewed the previous certificates are still valid. The solution to the above problem is therefore quite simple: continue to use the old certificate until the TLSA records for the new certificate are published, and only then have your service use the new certificate. This will work because as long as there exists one TLSA record that matches the certificate being offered, authentication will succeed: the existence of other TLSA records that do not match is not taken as an authentication failure as long as at least one record matches.

Operationally, however, this involves a little bit of work on the server to implement. There is where *Alnitak* can help.

## How Alnitak Works

### The Initial Setup

Back to the example above, suppose we are running a mail server at `smtp.example.com` on port 25 (or a web server at `www.example.com` on port 443, or...). Let's Encrypt is installed to provide "live certificates" in `/etc/letsencrypt/live/example.com/`, which are symbolic links to the actual "archive certificates" in `/etc/letsencrypt/archive/example.com/`. The Mail Transfer Agent that is listening on port 25 (postfix, exim, sendmail,...) will usually be configured to use the certificates in the "live directory". For example, for postfix:

    # /etc/postfix/main.cf
    smtpd_tls_cert_file = /etc/letsencrypt/live/example.com/fullchain.pem
    smtpd_tls_key_file = /etc/letsencrypt/live/example.com/privkey.pem

Note that in this example, the service is running on `smtp.example.com` but the certificate is located in `/etc/letsencrypt/live/example.com/`. This would be the case if you created a multi-domain or wildcard certificate. If a specific certificate for the `smtp.example.com` subdomain was created, it would be located in `/etc/letsencrypt/live/smtp.example.com/`. Either way will work fine in everything that follows.

### Alnitak

When *Alnitak* is first run it will create a new "dane directory" `/etc/alnitak/dane/`, which will imitate the structure of the Let's Encrypt "live directory". In other words, for every directory in `/etc/letsencrypt/live/`, there will be created an identically named directory in `/etc/alnitak/dane/`. Inside every such directory there will be created symbolic links named identically to the symbolic links in the "live directory", but instead of pointing to "archive certificates", these symbolic links will point to the live certificate symbolic links.

With the example above, your filesystem will look like this:

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
                ├── cert.pem@  ->  ../../live/example.com/cert.pem
                ├── chain.pem@  ->  ../../live/example.com/chain.pem
                ├── fullchain.pem@  ->  ../../live/example.com/fullchain.pem
                └── privkey.pem@  ->  ../../live/example.com/privkey.pem

Every service that then implements DANE with the help of *Alnitak* should then substitute certificates `/etc/letsencrypt/live/DOMAIN/X.pem` with `/etc/alnitak/dane/DOMAIN/X.pem`.

The master configuration file for *Alnitak* should then be edited to:

    # /etc/alntitak.conf
    [example.com]
    #      <params>  <port>  [protcol]  [domain]
    tlsa = 211       25                 smtp.example.com
    tlsa = 301       25                 smtp.example.com

Such an entry is called a "target", and consists of a section head containing the domain name that is the directory that the certificates are located in, followed by what TLSA records should be created when the certificates in that directory are renewed. Here, two TLSA records would be created:

    TLSA  2 1 1  _25._tcp.smtp.example.com
    TLSA  3 0 1  _25._tcp.smtp.example.com

Note that the protocol field may be omitted, in which case the protocol "tcp" will be used, and also that the domain field may be omitted, in which case the section domain name will be used. Here, the section domain (`example.com`), being the domain name the certificates are located in, and the domain to use in the TLSA record (`smtp.example.com`) differ, and thus we give an explicit value to the domain field.

In addition to targets, the master configuration file also needs to know how to to publish/delete DNS records. If your DNS settings are managed by Cloudflare, then this program can automatically do this for you. Otherwise, the program can call an external program to do this explicitly, which you may provide to the program. See the **API Schemes** section.

### Certificate Renewal

With the setup as above, this is what will happen when a certificate is renewed:

1. First, *Alnitak* will resolve the symbolic links in the "dane directory" so that instead of pointing to live certificates, they will point to the actual archive certificate. This produces no effect on the services using this dane certificate since whether it points to the live certificate or the archive certificate, they are functionally the same file.
2. Let's Encrypt performs a scheduled update and any certificates that are renewed have their domain added to the environment parameter `RENEWED_DOMAINS`.
3. *Alnitak* will then look for this environment parameter, and for every renewed domain publish a new TLSA record. Every domain that is not renewed has their dane directory symbolic links changed back to the live certificate symbolic links (so the situation is the same as it was before).
4. After a set period of time, *Alnitak* will check to see if the TLSA records published in step 3 are up. If so, *Alnitak* will delete any old TLSA records and move the dane certificate symbolic links to point back to the live certificates (so, they will now be pointing to the renewed certificates).

Let's Encrypt attempts to updates certificates twice daily (by default) via a cron job or a systemd timer. We simply need to amend this operation. By design, *Alnitak* is intended to run on the certbot pre- and post-hooks as:

    certbot renew --pre-hook "alnitak --pre" --post-hook "alnitak --post"

When the *Alnitak* commands is run as:

    alnitak --pre

it will perform step 1, as above. When run as:

    alnitak --post

it will perform step 3, as above.

In order to perform step 4, the user simply needs to run the program (without any flags) at any point:

    alnitak

When run like this, it will know if any TLSA records have been published recently and any dane certificates still need to be processed (moved back to pointing to live certificates). *Alnitak* can be run at any time and however many times you wish in order to do this: it has an internal time-to-live value before which it will not do any dane certificate processing. Thus, even if you call *Alnitak* straight away after a renewal it will not do any processing until at least this time-to-live value has passed in order to give the DNS some time to publish and promulgate the new records. (By default, this time-to-live value is 86400 seconds, but can be changed via a `--ttl` flag.)

## Installation

### Prerequisites

This program is only supported for python version 3.4 and newer. If building from source, you will need [libffi](https://github.com/libffi/libffi) and [libssl](https://www.openssl.org/). On older systems ensure that you have installed setuptools version 18.5 or newer.

The program has been tested on Debian (Jessie and Stretch). It should work for all Unix-like systems (or at least, all systems that provide fcntl, support for symbolic links and that follow the [Filesystem Hierarchy Standard](https://wiki.linuxfoundation.org/lsb/fhs)).

### Dependencies

* requests >= 2.21.0
* cryptography >= 2.4.2

These should automatically be installed when running any of the following commands.

### Development

    python setup.py develop

### Installation

    python setup.py install

### Tests

You should first enter "development mode" (see above) before running the tests, or else some tests will fail. To run the tests, run:

    python setup.py test

Note that although *Alnitak* needs root permissions to run, running the tests does not, even though the tests simulate runs of the program. Neither does the testing require any Let's Encrypt files to be present on the system. Finally, The tests do not write to any system files, so they should be safe to run.

### Running Alnitak

After installation, create a config file at `/etc/alnitak.conf` and add targets and API scheme(s) (a sample configuration file is included in the package). Then run the following command to initialize the dane directory and also check the config file for errors:

    alnitak --reset --config-test

The program is now ready to use. You can add the program to the certbot pre- and post-hooks by editing the configuration files in `/etc/letsencrypt/renewal/` by adding the lines:

    [renewalparams]
    pre_hook = alnitak --pre
    post_hook = alnitak --post

All that remains is to create a cron job or systemd timer to run the program (without flags):

    # crontab
    # run alnitak every day at 3am
    0 3 * * * alnitak

It is recommended to run this job/timer at least once a day (whenever you like).

## Configuration

The master configuration file `/etc/alnitak.conf` controls what TLSA records need to be managed. This configuration file should consist of one or more "targets" along with other miscellaneous commands.

### Targets

A "target" is essentially a list of TLSA records to publish when a domain (i.e., certificates inside of `/etc/letsencrypt/archive/DOMAIN/`) are renewed. A target is given by an ini-like section and looks like:

    [LE_DOMAIN]
    tlsa = PARAM PORT PROTOCOL DNS_DOMAIN

where:

* `LE_DOMAIN`: is the name of the directory in `/etc/letsencrypt/archive/` for which a certificate renewal should cause the publication of new TLSA records.
* `PARAM`: should be the parameters of the TLSA record (concatenated together). Only DANE-TA(2) and DANE-EE(3) will be supported.
* `PROTOCOL`: is the protocol field of the TLSA record. This field may be omitted, in which case the default value of "tcp" will be used.
* `DNS_DOMAIN`: is the domain field of the TLSA record. This field may be omitted, in which case `LE_DOMAIN` is used as the domain for the TLSA record.

More than one TLSA record may form a part of a target, in which case all the associated TLSA records will be published when the domain is renewed.

### API Schemes

When a domain is renewed and TLSA records need to be published (or deleted), *Alnitak* needs to know how to do this. In other words, some way to programmatically edit your DNS zone is required. *Alnitak* can either call an external program in order to do this or automatically do this for recognized DNS providers (currently only Cloudflare). The API scheme can be set as follows:

    api = SCHEME INPUTS...

which can either be placed outside of all targets, in which case it will apply to all the targets, or else can be placed within a target, in which case it will apply only to that target and override any previously specified scheme.

#### Cloudflare

If your DNS provider is Cloudflare, then *Alnitak* can automatically create/delete TLSA records as needed; all that is needed is your account email and password along with your zone ID. These can be provided directly:

    api = cloudflare4  email:EMAIL...  key:KEY...  zone:ZONE...

or else in a separate file:

    api = cloudflare4 FILE

where *FILE* should contain:

    # comments are allowed
    email = EMAIL...
    zone = ZONE...
    key = KEY...

Note that storing your password and login information in the configuration file directly may be less secure than in an external file since the configuration file might see more editing that a dedicated file, and hence increase the risk of an accidental release of that information. Since *Alnitak* needs root permission to run, the dedicated password file ought to restrict read/write permissions as much as possible: as long as the file is readable to root should suffice.

#### External Program

To call an external program to create or delete TLSA records, use:

    api = binary COMMAND FLAGS...

which will call *COMMAND* as needed. Any flags specified here will be passed on to the command and quoting of inputs is respected. The external program must be able to create and delete TLSA records, and should distinguish between these two operations by reading the environment for a parameter called `TLSA_OPERATION`:

##### publishing records

The environment parameter `TLSA_OPERATION` will be set to the value "publish". The program should exit with code:

    0  -  if the TLSA record was published successfully,
    1  -  if the TLSA record is already up,
    2+ -  if an error occurred.

##### deleting records

The environment parameter `TLSA_OPERATION` will be set to the value "delete". Additionally, the environment parameter `TLSA_LIVE_HASH` may be present. When so present, it will contain the TLSA record "certificate data" of the new TLSA record that should be up; the external program should not delete the old TLSA record until it has verified that the new TLSA record is indeed up. The program should exit with code:

    0  -  if the old record was deleted successfully,
    1  -  if the new record was not up yet, so the old one should not be deleted yet,
    2+ -  if an error occurred.

Whether creating or deleting DNS records, the environment will also have set the parameters:

* `PATH`: set to "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
* `IFS`: set to " \t\n"
* `TLSA_USAGE`: set to the "usage field" of the TLSA record parameters.
* `TLSA_SELECTOR`: set to the "selector field" of the TLSA record parameters.
* `TLSA_MATCHING`: set to the "matching-type field" of the TLSA record parameters.
* `TLSA_PARAM`: set to the full (concatenated) TLSA parameter, formed by concatenating the usage, selector and matching type fields.
* `TLSA_PORT`: set to the TLSA record port.
* `TLSA_PROTOCOL`: set to the TLSA record protocol.
* `TLSA_DOMAIN`: set to the TLSA record domain.
* `TLSA_HASH`: set to the TLSA record "certificate data" field. This is the certificate-dependent part of the TLSA record to publish/delete.

See the included file `sample-api.sh` for a basic template of how the external program should operate.

### Miscellaneous Commands

These commands modify the operation of the program. They all have command-line flag equivalents:

##### dane_directory

Set the directory that will contain the domain directories. By default this is set to `/etc/alnitak/dane/`. You can change it to another location by specifying:

    dane_directory = PATH

Note that it is probably unwise to set it to `/etc/letsencrypt/dane/` since you would not want any other program potentially interfering with this directory.

The command-line equivalent is:

    alnitak --dane-directory PATH

##### letsencrypt_directory

Set to the directory that contains the Let's Encrypt live and archive directories. By default this is set to `/etc/letsencrypt/`. You shouldn't need to change this unless you have an unusual setup, but you can by specifying:

    letsencrypt_directory = PATH

The command-line equivalent is:

    alnital --letsencrypt-directory PATH

##### ttl

Set the time-to-live value (in integer seconds) before which no deletion of old TLSA records can be done. This parameter is used to give the DNS infrastructure time to publish and promulgate any new TLSA records before any further processing can be done. The default value is 86400, which is 1 day. This value is more than enough time, but you can set it to a lower value if you wish by specifying:

    ttl = SECONDS

The command-line equivalent is:

    alnitak --ttl SECONDS

## Program Invocation

Apart from the program flags listed above, the following flags are also provided:

##### --reset

This flag will reset the dane directory so that all the dane symbolic links point to the live certificates. This command will also make sure that the dane directory is set up correctly. You can use this command upon first installation to create the dane directory, but otherwise you shouldn't need it unless something has gone wrong.

##### --config-test, -t

Will check the configuration file for errors. It is recommended you run this after all changes to the configuration file.

##### --config, -c FILE

Read the specified configuration file *FILE* instead of the default file.

##### --log, -l FILE

Log to the specified file rather than the default `/var/log/alnitak.log`. The parent directory must already exist, but if the log file is missing it will be created. If the value given is "stdout" or "-", logging will be sent standard output. Logging can also be disabled by passing the value "no". (If you want to log to a file named, for example, "no", just pass something like "./no" instead.)

##### --log-level, -L LEVEL

Set the level of detail of information to log. The allowed values, in increasing order of detail, are: "no", "normal", "verbose" and "full". The default is "normal". A value of "no" will only log errors.

##### --quiet, -q

Do not print messages to stdout or stderr during the execution of the program. This does not include error messages related to errors of invocation on the command-line, however: these will still be printed to stderr even if the `--quiet` flag has been given.

### Logging

By default, the program will log information to the file `/var/log/alnitak.log` (which can be changed via the `--log` flag). The following combination of flags provide a guide as to how the program will print errors and information, and where to. You will likely only ever need a few of these scenarios, but they are all listed for the sake of completion.

|     flags     |     errors      |  info   |
|:--------------|:---------------:|:-------:|
|<none>         | logfile, stderr | logfile |
|`-l-`          | stderr          | stdout  |
|`-lno`         | stderr          | -       |
|`-q`           | logfile         | logfile |
|`-l- -q`       | -               | -       |
|`-lno -q`      | -               | -       |
|`-Lno`         | logfile, stderr | -       |
|`-l- -Lno`     | stderr          | -       |
|`-lno -Lno`    | stderr          | -       |
|`-q -Lno`      | logfile         | -       |
|`-l- -q -Lno`  | -               | -       |
|`-lno -q -Lno` | -               | -       |

As a general rule of thumb: by default, all messages (info or errors) are written to the logfile, with the error messages also written to stderr. If you want to write to stdout rather than to the logfile, then pass the `-l-` (`--log=stdout`) flag. If you want to only ever write to the logfile, then pass the `-q` flag. If you want to suppress all info output, pass the `-Lno` flag.

## Exit Codes

The program will exit with the following codes:

* 0: program executed without errors.
* 1: program encountered errors during execution.
* 2: command-line errors.
* 3: syntax errors in the configuration file.
* 4: error in creating a lock file: program aborted.

If there has been a problem in writing output (e.g. to the logfile), some of
the exit codes above will be increased in value by 16:

* 16: program executed fine, but logging errors encountered.
* 17: program encountered errors in execution and also logging encountered errors.
* 19: syntax errors in the configuration file and logging errors encountered.

Finally, if the program is run whilst a lock is already active, the program will exit with code:

* 32: another instance of the program is already running.

## Contributing

This program can manage Cloudflare DNS zones since that is what I am using. If you would like the program to automatically manage a different provider, then you can look at the file `alnitak/api/cloudflare4.py` to see how I use the requests package to call the Cloudflare REST API. If you can test some basic code that can call your own provider, then I can integrate it into the program myself: primarily I just need to know the commands to GET, POST and DELETE records that will work, and what responses are returned upon both success and failure.

## Licence

This code is beta software. Use at your own risk.

This program is released under the MIT Licence.

#### MIT License

##### Copyright (c) 2019 K. S. Kooner

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
