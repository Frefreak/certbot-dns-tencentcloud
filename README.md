# certbot-dns-tencentcloud

This package provides a Certbot authenticator plugin
that can complete the DNS-01 challenge using the Tencent Cloud API.


## Installation

Only Tested on python 3.8, should work on python 3.7 too and forward.

- no plan to support python2
- [dataclasses](https://docs.python.org/3/library/dataclasses.html) is used, so python 3.6 and down will not work. However you can try installing `dataclasses` from pypi.

Use pip to install this package:
```
sudo pip3 install certbot-dns-tencentcloud
```

Verify the installation with Certbot:
```
sudo certbot plugins
```
You should see `dns-tencentcloud` in the output.


## Usage

To use this plugin, set the authenticator to `dns-tencentcloud` via the `-a` or `--authenticator` flag.
You may also set this using Certbot's configuration file (defaults to `/etc/letsencrypt/cli.ini`).

You will also need to provide a credentials file with your Tencent Cloud API key id and secret, like the following:
```
dns_tencentcloud_secret_id  = TENCENTCLOUD_SECRET_ID
dns_tencentcloud_secret_key = TENCENTCLOUD_SECRET_KEY
```
The path to this file can be provided interactively or via the `--dns-tencentcloud-credentials` argument.

You can also provide the credential using `TENCENTCLOUD_SECRET_ID`
and `TENCENTCLOUD_SECRET_KEY` environment variables.

**CAUTION:**
Protect your API key as you would the password to your account.
Anyone with access to this file can make API calls on your behalf.
Be sure to **read the security tips below**.


### Arguments

- `--dns-tencentcloud-credentials` path to Tencent Cloud credentials INI file (Required)
- `--dns-tencentcloud-propagation-seconds` seconds to wait before verifying the DNS record (Default: 10)

**NOTE:** Due to a [limitation in Certbot](https://github.com/certbot/certbot/issues/4351),
these arguments *cannot* be set via Certbot's configuration file.


### Example

When in root:

```
certbot certonly \
  -a dns-tencentcloud \
  --dns-tencentcloud-credentials ~/.secrets/certbot/tencentcloud.ini \
  -d example.com
```

or if providing credentials using environment variable:

```
export TENCENTCLOUD_SECRET_ID=<your_secret_id> TENCENTCLOUD_SECRET_KEY=<your_secret_key>
certbot certonly \
  -a dns-tencentcloud \
  -d example.com
```


### Security Tips

**Restrict access of your credentials file to the owner.**
You can do this using `chmod 600`.
Certbot will emit a warning if the credentials file
can be accessed by other users on your system.

**Use a separate key from your account's primary API key.**
Make a separate user under your account,
and limit its access to only allow DNS access
and the IP address of the machine(s) that will be using it.

### FAQ

1. Which strategy should I choose to limit my API key access to only allow DNS resolution related operation?

We now use the new DNSPOD api so you need to give `QcloudDNSPodFullAccess` strategy (need to add record so write permission is necessary).

2. renew certs for `*.abc.com` and `abc.com` at the same time sometimes show error about incorrect TXT records.

It seems Let's Encrypt cache TXT records for at most 60 seconds, since DNSPod doesn't seem
to allow setting TXT record's TTL below 60, in this case the best/safest way is to set
`--dns-tencentcloud-propagation-seconds` longer than 60.

3. Debug mode?

```
--dns-tencentcloud-debug true
```
