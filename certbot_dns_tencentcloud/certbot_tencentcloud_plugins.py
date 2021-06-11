import json
import random
import time
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
        self.base_domain = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add("credentials", help="TencentCloud credentials INI file.")

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

    def determine_base_domain(self, domain):
        client = TencentCloudClient(
            self.credentials.conf("secret_id"), self.credentials.conf("secret_key")
        )
        segments = domain.split(".")
        tried = []
        i = len(segments) - 2
        while i >= 0:
            dt = ".".join(segments[i:])
            tried.append(dt)
            i -= 1
            try:
                client.get_record_list(dt)
            # if error, we don't seem to own this domain
            except APIException as _:
                continue
            return dt, tried
        return None, tried

    # pylint: enable=no-self-use

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "TencentCloud credentials INI file",
            None,
            self._validate_credentials,
        )

    def _perform(self, domain, validation_name, validation):
        client = TencentCloudClient(
            self.credentials.conf("secret_id"), self.credentials.conf("secret_key")
        )
        base_domain, tried = self.determine_base_domain(domain)
        if base_domain is None:
            raise ValueError(
                "failed to determine base domain, please report to dev. "
                f"Tried: {tried}"
            )
        self.base_domain = base_domain
        if not validation_name.endswith("." + base_domain):
            raise ValueError(
                "validation_name not ends with base domain name, please report to dev. "
                f"real_domain: {base_domain}, validation_name: {validation_name}"
            )
        sub_domain = validation_name[: -(len(base_domain) + 1)]
        resp = client.get_record_list(base_domain, sub_domain)
        rid = None
        if int(resp["info"]["record_total"]) > 0:
            rid = resp["records"][0]["id"]
        if rid is None:
            client.get_record_create(base_domain, sub_domain, "TXT", validation)
        else:
            client.get_record_modify(base_domain, rid, sub_domain, "TXT", validation)

    def _cleanup(self, domain, validation_name, validation):
        client = TencentCloudClient(
            self.credentials.conf("secret_id"), self.credentials.conf("secret_key")
        )
        if self.base_domain is None:
            return
        base_domain = self.base_domain
        sub_domain = validation_name[: -(len(base_domain) + 1)]
        resp = client.get_record_list(base_domain, sub_domain)
        rid = None
        if int(resp["info"]["record_total"]) > 0:
            rid = resp["records"][0]["id"]
        if rid is None:
            raise errors.PluginError(
                "could not find record in cleanup: {}".format(validation_name)
            )
        client.get_record_delete(base_domain, rid)


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

    def __init__(self, secret_id, secret_key):
        self.cred = self.Cred(secret_id, secret_key)

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
        signature = self._mk_sign("GET", params)
        params["Signature"] = signature
        full_url = (
            self.url
            + "?"
            + "&".join([quote(str(k)) + "=" + quote(str(v)) for k, v in params.items()])
        )
        rj = json.loads(urlopen(full_url).read().decode())
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
