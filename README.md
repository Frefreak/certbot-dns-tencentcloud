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
You should see `dns-tencentcloud` in the output.


## Usage

To use this plugin, set the authenticator to `dns-tencentcloud` via the `-a` or `--authenticator` flag.
You may also set this using Certbot's configuration file (defaults to `/etc/letsencrypt/cli.ini`).

You will also need to provide a credentials file with your Tencent Cloud API key id and secret, like the following:
```
dns_tencentcloud_secret_id  = TENCENT_CLOUD_SECRET_ID
dns_tencentcloud_secret_key = TENCENT_CLOUD_SECRET_KEY
```
The path to this file can be provided interactively or via the `--dns-tencentcloud-credentials` argument.

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

```
certbot certonly \
  -a dns-tencentcloud \
  --dns-tencentcloud-credentials ~/.secrets/certbot/tencentcloud.ini \
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

~~Currently it seems there's no specific strategy corresponding to this, and sadly the only strategy I tried that worked is **QCloudResourceFullAccess**. Trying to negotiate with tencent cloud team to support this is on my todo-list though.~~

Response Updated: 感谢反馈。DNS 解析已有 QCloudCNSFullAccess 策略，但需要加白才可使用。后续 DNS 解析会接入 CAM 。

DNS reslution now already has QCloudCNSFullAccess strategy, but needs whitelist to be able to use (probably needs ticket?). Later this will be added to CAM (If I understand correctly this means it will be available just like other strategies).
