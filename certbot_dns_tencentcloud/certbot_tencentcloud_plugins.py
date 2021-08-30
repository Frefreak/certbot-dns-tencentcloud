import json
import hashlib
import sys
import random
import time
from datetime import datetime
import os
from base64 import b64encode
from typing import Dict, Tuple, Optional
from dataclasses import dataclass
from hmac import HMAC
from urllib.parse import quote
from urllib.request import urlopen, Request

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
        self.secret_id = None
        self.secret_key = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add(
            "credentials",
            help="TencentCloud credentials INI file. If omitted, the environment variables TENCENTCLOUD_SECRET_ID and TENCENTCLOUD_SECRET_KEY will be tried",
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
                resp = client.describe_record_list(dt)
            # if error, we don't seem to own this domain
            except APIException as _:
                continue
            return dt, resp["RecordList"]
        raise errors.PluginError(
            "failed to determine base domain, please report to dev. " f"Tried: {tried}"
        )

    # pylint: enable=no-self-use

    def _setup_credentials(self):
        if self.conf("credentials"):
            credentials = self._configure_credentials(
                "credentials",
                "TencentCloud credentials INI file",
                None,
                self._validate_credentials,
            )
            self.secret_id = credentials.conf("secret_id")
            self.secret_key = credentials.conf("secret_key")
        else:
            self.chk_environ_exist("TENCENTCLOUD_SECRET_ID")
            self.chk_environ_exist("TENCENTCLOUD_SECRET_KEY")
            self.secret_id = os.environ.get("TENCENTCLOUD_SECRET_ID")
            self.secret_key = os.environ.get("TENCENTCLOUD_SECRET_KEY")

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
        _ = client.create_record(base_domain, sub_domain, "TXT", validation)

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
            if rec["Type"] == "TXT" and rec["Value"] == validation:
                client.delete_record(base_domain, rec["RecordId"])


class APIException(Exception):
    pass


class TencentCloudClient:
    """Simple specialized client for dnspod API."""

    @dataclass
    class Cred:
        secret_id: str
        secret_key: str

    host = "dnspod.tencentcloudapi.com"
    url = "https://" + host
    algorithm = "TC3-HMAC-SHA256"
    version = "2021-03-23"

    def __init__(self, secret_id, secret_key, debug=False):
        self.cred = self.Cred(secret_id, secret_key)
        self.debug = debug

    def _mk_post_sign_v3(self, payload: Dict) -> Dict:
        now = datetime.now()
        now_timestamp = int(now.timestamp())
        date = now.strftime("%Y-%m-%d")
        headers = {
            "Something-Random": random.getrandbits(64),
            "Content-Type": "application/json; charset=utf-8",
            "Host": self.host,
            "X-TC-Timestamp": now_timestamp,
        }
        canonical_headers = "\n".join(
            [k.lower() + ":" + str(headers[k]).lower() for k in sorted(headers)]
        )
        signed_headers = ";".join([k.lower() for k in sorted(headers)])
        hashed_request_payload = hashlib.sha256(
            json.dumps(payload).encode()
        ).hexdigest()
        canonical_request = [
            "POST",
            "/",
            "",
            canonical_headers,
            "",
            signed_headers,
            hashed_request_payload,
        ]
        hashed_canonical_request = hashlib.sha256(
            "\n".join(canonical_request).encode()
        ).hexdigest()
        service, ending = ("dnspod", "tc3_request")
        credential_scope = f"{date}/{service}/{ending}"
        string_to_sign = "\n".join(
            [
                self.algorithm,
                str(now_timestamp),
                credential_scope,
                hashed_canonical_request,
            ]
        )
        secret_date = HMAC(
            ("TC3" + self.cred.secret_key).encode(), date.encode(), "sha256"
        ).digest()
        secret_service = HMAC(secret_date, service.encode(), "sha256").digest()
        secret_signing = HMAC(secret_service, ending.encode(), "sha256").digest()
        sig = HMAC(secret_signing, string_to_sign.encode(), "sha256").hexdigest()
        authorization = (
            self.algorithm
            + " "
            + "Credential="
            + self.cred.secret_id
            + "/"
            + credential_scope
            + ", "
            + "SignedHeaders="
            + signed_headers
            + ", "
            + "Signature="
            + sig
        )
        headers["Authorization"] = authorization
        return headers

    def mk_post_req(self, action: str, payload: Dict) -> Dict:
        headers = self._mk_post_sign_v3(payload)
        headers["X-TC-Action"] = action
        headers["X-TC-Version"] = self.version
        request = Request(self.url, json.dumps(payload).encode(), headers)
        rj = json.loads(urlopen(request).read().decode())
        resp = rj["Response"]
        if "Error" in resp:
            raise APIException(resp["Error"])
        return resp

    def describe_domain(self, domain: str) -> Dict:
        payload = {
            "Domain": domain,
        }
        return self.mk_post_req("DescribeDomain", payload)

    def describe_record_list(self, domain: str) -> Dict:
        payload = {
            "Domain": domain,
        }
        return self.mk_post_req("DescribeRecordList", payload)

    def create_record(
        self, domain: str, sub_domain: str, record_type: str, value: str
    ) -> Dict:
        payload = {
            "Domain": domain,
            "RecordType": record_type,
            "RecordLine": "默认",
            "SubDomain": sub_domain,
            "Value": value,
        }
        return self.mk_post_req("CreateRecord", payload)

    def modify_record(
        self, domain: str, rid: int, sub_domain: str, record_type: str, value: str
    ) -> Dict:
        payload = {
            "Domain": domain,
            "RecordType": record_type,
            "RecordLine": "默认",
            "SubDomain": sub_domain,
            "Value": value,
            "RecordId": rid,
        }
        return self.mk_post_req("ModifyRecord", payload)

    def delete_record(self, domain: str, rid: int):
        payload = {
            "Domain": domain,
            "RecordId": rid,
        }
        return self.mk_post_req("DeleteRecord", payload)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    secret_id = os.getenv("SECRET_ID")
    secret_key = os.getenv("SECRET_KEY")
    if not secret_id or not secret_key:
        print("SECRET_ID && SECRET_KEY")
        sys.exit(1)
    cli = TencentCloudClient(secret_id, secret_key)
    r = cli.describe_domain(domain)
    sub = f"test-{random.getrandbits(32)}"

    print(
        "following operations might render your domain with un-cleaned up test record if something wrong happens in the middle."
    )
    input("enter to continue...")

    print("creating record...")
    r = cli.create_record(
        domain, sub, "TXT", datetime.now().strftime("%Y%m%d %H:%M:%S")
    )
    print(
        f"now please lookup TXT record of {sub}.{domain}, might need some secs to propagate"
    )
    input("enter to continue...")

    print("modifying record...")
    r = cli.describe_record_list(domain)
    rid = None
    for rec in r["RecordList"]:
        if rec["Name"] == sub:
            rid = rec["RecordId"]
            break
    if rid is None:
        print("weird, new record not found, exiting...")
        sys.exit(1)
    r = cli.modify_record(
        domain, rid, sub, "TXT", datetime.now().strftime("%Y%m%d %H:%M:%S")
    )
    print(
        f"now please lookup TXT record of {sub}.{domain} again (probably need to wait ~60s)"
    )
    input("enter to continue...")

    print("deleting record...")
    r = cli.delete_record(domain, rid)
    print("you can check now its deleted")
