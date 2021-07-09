import json
import random
import time
import os
from base64 import b64encode
from dataclasses import dataclass
from hmac import HMAC
from urllib.parse import quote
from urllib.request import urlopen

import zope.interface
from certbot import errors, interfaces
from certbot.plugins import dns_common


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for TencentCloud

    This Authenticator uses the TencentCloud API to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record (if you are "
        "using TencentCloud for DNS)."
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials = None
        self.secret_id = None
        self.secret_key = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add(
            "credentials",
            help="TencentCloud credentials INI file. If omit will look up environments for TENCENT_CLOUD_SECRET_ID, TENCENT_CLOUD_SECRET_KEY",
        )
        add(
            "debug",
            help="turn on debug mode (print some debug info)",
            type=bool,
            default=False,
        )

    # pylint: disable=no-self-use
    def more_info(self):  # pylint: disable=missing-function-docstring
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the TencentCloud API."
        )

    def _validate_credentials(self, credentials):
        self.chk_exist(credentials, "secret_id")
        self.chk_exist(credentials, "secret_key")

    def chk_exist(self, credentials, arg):
        v = credentials.conf(arg)
        if not v:
            raise errors.PluginError("{} is required".format(arg))

    def chk_environ_exist(self, arg):
        if os.environ.get(arg) is None:
            print(os.environ)
            raise errors.PluginError("The environment {} is required".format(arg))

    def chk_base_domain(self, base_domain, validation_name):
        if not validation_name.endswith("." + base_domain):
            raise errors.PluginError(
                "validation_name not ends with base domain name, please report to dev. "
                f"real_domain: {base_domain}, validation_name: {validation_name}"
            )

    def determine_base_domain(self, domain):
        if self.conf("debug"):
            print("finding base domain")
        client = TencentCloudClient(
            self.secret_id,
            self.secret_key,
            self.conf("debug"),
        )
        segments = domain.split(".")
        tried = []
        i = len(segments) - 2
        while i >= 0:
            dt = ".".join(segments[i:])
            tried.append(dt)
            i -= 1
            try:
                resp = client.get_record_list(dt)
            # if error, we don't seem to own this domain
            except APIException as _:
                continue
            return dt, resp["records"]
        raise errors.PluginError(
            "failed to determine base domain, please report to dev. " f"Tried: {tried}"
        )

    # pylint: enable=no-self-use

    def _setup_credentials(self):
        if self.conf("credentials"):
            self.credentials = self._configure_credentials(
                "credentials",
                "TencentCloud credentials INI file",
                None,
                self._validate_credentials,
            )
            self.secret_id=self.credentials.conf("secret_id")
            self.secret_key=self.credentials.conf("secret_key")
        else:
            self.chk_environ_exist("TENCENTCLOUD_SECRET_ID")
            self.chk_environ_exist("TENCENTCLOUD_SECRET_KEY")
            self.secret_id=os.environ.get("TENCENTCLOUD_SECRET_ID")
            self.secret_key=os.environ.get("TENCENTCLOUD_SECRET_KEY")

    def _perform(self, domain, validation_name, validation):
        if self.conf("debug"):
            print("perform", domain, validation_name, validation)
        client = TencentCloudClient(
            self.secret_id,
            self.secret_key,
            self.conf("debug"),
        )
        base_domain, _ = self.determine_base_domain(domain)
        self.chk_base_domain(base_domain, validation_name)

        sub_domain = validation_name[: -(len(base_domain) + 1)]
        resp = client.get_record_create(base_domain, sub_domain, "TXT", validation)

    def _cleanup(self, domain, validation_name, validation):
        if self.conf("debug"):
            print("cleanup", domain, validation_name, validation)
        client = TencentCloudClient(
            self.secret_id,
            self.secret_key,
            self.conf("debug"),
        )
        base_domain, records = self.determine_base_domain(domain)
        self.chk_base_domain(base_domain, validation_name)
        for rec in records:
            if rec["type"] == "TXT" and rec["value"] == validation:
                client.get_record_delete(base_domain, rec["id"])


class APIException(Exception):
    pass


class TencentCloudClient:
    """Specifically used for domain DNS management."""

    @dataclass
    class Cred:
        secret_id: str
        secret_key: str

    endpoint = "cns.api.qcloud.com/v2/index.php"
    url = "https://" + endpoint

    def __init__(self, secret_id, secret_key, debug=False):
        self.cred = self.Cred(secret_id, secret_key)
        self.debug = debug

    def _expand_params(self, action, params):
        params.update(
            {
                "Action": action,
                "SecretId": self.cred.secret_id,
                "Timestamp": int(time.time()),
                "Nonce": random.randrange(10000),
                "Region": "ap-shanghai",  # not important
                "SignatureMethod": "HmacSHA256",  # stick to sha256
            }
        )

    def _mk_sign(self, verb, params):
        s = []
        for k, v in sorted(params.items()):
            s.append("{}={}".format(k.replace("_", "."), v))
        sign_str = verb + self.endpoint + "?" + "&".join(s)
        return b64encode(
            HMAC(self.cred.secret_key.encode(), sign_str.encode(), "sha256").digest()
        ).decode()

    def mk_get_req(self, action, params):
        self._expand_params(action, params)
        if self.debug:
            print(f"\x1b[32;1m{action}\x1b[0m params: {params}")
        signature = self._mk_sign("GET", params)
        params["Signature"] = signature
        full_url = (
            self.url
            + "?"
            + "&".join([quote(str(k)) + "=" + quote(str(v)) for k, v in params.items()])
        )
        rj = json.loads(urlopen(full_url).read().decode())
        if self.debug:
            print(f"\x1b[31;1m{action}\x1b[31;0m resp: {rj}")
        if rj["code"] == 0:
            if "data" in rj:  # only exception is delete
                return rj["data"]
            return {}
        raise APIException(f'{action}: {rj["message"]}')

    def get_record_list(self, domain, sub_domain=None):
        """Currently does not care about pagination."""
        params = dict(domain=domain)
        if sub_domain is not None:
            params["subDomain"] = sub_domain
        return self.mk_get_req("RecordList", params)

    def get_record_create(self, domain, sub_domain, record_type, value):
        params = dict(
            domain=domain,
            subDomain=sub_domain,
            recordType=record_type,
            recordLine="默认",
            value=value,
        )
        return self.mk_get_req("RecordCreate", params)

    # pylint: disable=too-many-arguments
    def get_record_modify(self, domain, rid, sub_domain, record_type, value):
        params = dict(
            domain=domain,
            recordId=rid,
            subDomain=sub_domain,
            recordType=record_type,
            recordLine="默认",
            value=value,
        )
        return self.mk_get_req("RecordModify", params)

    # pylint: enable=too-many-arguments

    def get_record_delete(self, domain, rid):
        params = dict(
            domain=domain,
            recordId=rid,
        )
        return self.mk_get_req("RecordDelete", params)
