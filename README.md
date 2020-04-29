# certbot-dns-tencentcloud

This package provides a Certbot authenticator plugin
that can complete the DNS-01 challenge using the Tencent Cloud API.


## Installation

Only Tested on python 3.8, should work on python 3.7 too.

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
You should see `certbot-dns-tencentcloud:dns-tencentcloud` in the output.


## Usage

To use this plugin, set the authenticator to `certbot-dns-tencentcloud:dns-tencentcloud` via the `-a` or `--authenticator` flag.
You may also set this using Certbot's configuration file (defaults to `/etc/letsencrypt/cli.ini`).

You will also need to provide a credentials file with your Tencent Cloud API key id and secret, like the following:
```
certbot_dns_tencentcloud:dns_tencentcloud_secret_id  = TENCENT_CLOUD_SECRET_ID
certbot_dns_tencentcloud:dns_tencentcloud_secret_key = TENCENT_CLOUD_SECRET_KEY
```
The path to this file can be provided interactively or via the `--certbot-dns-tencentcloud:dns-tencentcloud-credentials` argument.

**CAUTION:**
Protect your API key as you would the password to your account.
Anyone with access to this file can make API calls on your behalf.
Be sure to **read the security tips below**.


### Arguments

- `--certbot-dns-tencentcloud:dns-tencentcloud-credentials` path to Tencent Cloud credentials INI file (Required)
- `--certbot-dns-tencentcloud:dns-tencentcloud-propagation-seconds` seconds to wait before verifying the DNS record (Default: 10)

**NOTE:** Due to a [limitation in Certbot](https://github.com/certbot/certbot/issues/4351),
these arguments *cannot* be set via Certbot's configuration file.


### Example

```
certbot certonly \
  -a certbot-dns-tencentcloud:dns-tencentcloud \
  --certbot-dns-tencentcloud:dns-tencentcloud-credentials ~/.secrets/certbot/tencentcloud.ini \
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
