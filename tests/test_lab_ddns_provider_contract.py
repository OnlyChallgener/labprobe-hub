import json
import itertools
import tempfile
from pathlib import Path

import pytest
import requests

import lab_ddns
from lab_ddns import LabDdnsStore
from lab_ddns_providers import (
    AliDnsProvider,
    CloudflareProvider,
    DeSecProvider,
    DnsPodProvider,
    DuckDnsProvider,
    DynuProvider,
    Dynv6Provider,
    IPv64Provider,
)


class FakeResponse:
    def __init__(self, payload=None, text=None, status_code=200):
        self.payload = payload
        self.text = text if text is not None else json.dumps(payload or {})
        self.status_code = status_code

    def json(self):
        if self.payload is not None:
            return self.payload
        return json.loads(self.text)


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


class RaisingSession:
    def __init__(self, secret):
        self.secret = secret
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        raise requests.RequestException(f"request failed: {url}?token={self.secret}")


CASES = {
    "alidns": {
        "provider": AliDnsProvider,
        "credentials": {"AccessKeyId": "contract-id", "AccessKeySecret": "contract-secret", "zone": "example.com"},
        "hostname": "home.example.com",
        "success": lambda: [
            FakeResponse({"DomainRecords": {"Record": []}}),
            FakeResponse({"RecordId": "a-1"}),
        ],
        "failure": lambda secret: [FakeResponse({"Code": "ProviderError", "Message": secret}, status_code=500)],
        "auth": lambda status: [FakeResponse({}, status_code=status)],
        "rate": lambda: [FakeResponse({}, status_code=429)],
    },
    "dnspod": {
        "provider": DnsPodProvider,
        "credentials": {"SecretId": "contract-id", "SecretKey": "contract-secret", "zone": "example.com"},
        "hostname": "home.example.com",
        "success": lambda: [
            FakeResponse({"Response": {"RecordList": []}}),
            FakeResponse({"Response": {"RecordId": "a-1"}}),
        ],
        "failure": lambda secret: [FakeResponse({"Response": {"Error": {"Code": "ProviderError", "Message": secret}}}, status_code=500)],
        "auth": lambda status: [FakeResponse({"Response": {}}, status_code=status)],
        "rate": lambda: [FakeResponse({"Response": {}}, status_code=429)],
    },
    "cloudflare": {
        "provider": CloudflareProvider,
        "credentials": {"apiToken": "contract-secret", "zoneId": "zone-1"},
        "hostname": "home.example.com",
        "success": lambda: [FakeResponse({"success": True, "result": []}), FakeResponse({"success": True, "result": {"id": "cf-1"}})],
        "failure": lambda secret: [FakeResponse({"success": False, "errors": [{"code": 1000, "message": secret}]}, status_code=500)],
        "auth": lambda status: [FakeResponse({}, status_code=status)],
        "rate": lambda: [FakeResponse({}, status_code=429)],
    },
    "dynv6": {
        "provider": Dynv6Provider,
        "credentials": {"token": "contract-secret"},
        "hostname": "home.dynv6.net",
        "success": lambda: [FakeResponse(text="good")],
        "failure": lambda secret: [FakeResponse(text=f"provider failure {secret}", status_code=500)],
        "auth": lambda status: [FakeResponse(text="unauthorized", status_code=status)],
        "rate": lambda: [FakeResponse(text="rate limited", status_code=429)],
    },
    "duckdns": {
        "provider": DuckDnsProvider,
        "credentials": {"token": "contract-secret"},
        "hostname": "home.duckdns.org",
        "success": lambda: [FakeResponse(text="OK")],
        "failure": lambda secret: [FakeResponse(text=f"provider failure {secret}", status_code=500)],
        "auth": lambda status: [FakeResponse(text="unauthorized", status_code=status)],
        "rate": lambda: [FakeResponse(text="rate limited", status_code=429)],
    },
    "desec": {
        "provider": DeSecProvider,
        "credentials": {"token": "contract-secret"},
        "hostname": "home.dedyn.io",
        "success": lambda: [FakeResponse(text="good")],
        "failure": lambda secret: [FakeResponse(text=f"provider failure {secret}", status_code=500)],
        "auth": lambda status: [FakeResponse(text="unauthorized", status_code=status)],
        "rate": lambda: [FakeResponse(text="rate limited", status_code=429)],
    },
    "dynu": {
        "provider": DynuProvider,
        "credentials": {"username": "contract-user", "password": "contract-secret"},
        "hostname": "home.example.com",
        "success": lambda: [FakeResponse(text="good")],
        "failure": lambda secret: [FakeResponse(text=f"provider failure {secret}", status_code=500)],
        "auth": lambda status: [FakeResponse(text="unauthorized", status_code=status)],
        "rate": lambda: [FakeResponse(text="rate limited", status_code=429)],
    },
    "ipv64": {
        "provider": IPv64Provider,
        "credentials": {"token": "contract-secret"},
        "hostname": "home.ipv64.net",
        "success": lambda: [FakeResponse(text='{"status":"success"}')],
        "failure": lambda secret: [FakeResponse(text=f"provider failure {secret}", status_code=500)],
        "auth": lambda status: [FakeResponse(text="unauthorized", status_code=status)],
        "rate": lambda: [FakeResponse(text="rate limited", status_code=429)],
    },
}

PROVIDER_IDS = tuple(CASES)
RECORD_TYPES = ("A", "AAAA")


def make_provider(provider_id, responses):
    case = CASES[provider_id]
    return case["provider"](FakeSession(responses))


@pytest.mark.parametrize("provider_id", PROVIDER_IDS)
def test_registry_and_capability_contract(provider_id):
    provider = lab_ddns.PROVIDERS[provider_id]
    assert provider.provider_id == provider_id
    spec = next(item for item in lab_ddns.provider_specs() if item["id"] == provider_id)
    assert spec["supportsA"] is True
    assert spec["supportsAAAA"] is True


@pytest.mark.parametrize("provider_id", PROVIDER_IDS)
def test_missing_credentials_are_local_and_uniform(provider_id):
    session = FakeSession([])
    provider = CASES[provider_id]["provider"](session)
    result = provider.sync_record(CASES[provider_id]["hostname"], "A", "198.51.100.30", 600, {})
    assert result.ok is False
    assert result.error_code in {"credential_error", "authentication_failed"}
    assert session.calls == []


@pytest.mark.parametrize("provider_id,record_type", tuple(itertools.product(PROVIDER_IDS, RECORD_TYPES)))
def test_success_contract_is_record_type_specific(provider_id, record_type):
    case = CASES[provider_id]
    provider = make_provider(provider_id, case["success"]())
    value = "198.51.100.30" if record_type == "A" else "2001:db8::30"
    result = provider.sync_record(case["hostname"], record_type, value, 600, case["credentials"])
    assert result.ok is True
    assert result.status == "success"
    assert result.provider == provider_id
    assert result.record_type == record_type


@pytest.mark.parametrize(
    "record_type,operation,input_ttl,expected_ttl",
    tuple(
        (record_type, operation, input_ttl, expected_ttl)
        for record_type, operation, (input_ttl, expected_ttl) in itertools.product(
            RECORD_TYPES,
            ("create", "update"),
            ((60, 600), (600, 600), (86400, 86400), (86401, 86400)),
        )
    ),
)
def test_alidns_ttl_contract_is_valid_for_create_and_update(
    record_type, operation, input_ttl, expected_ttl
):
    case = CASES["alidns"]
    value = "198.51.100.30" if record_type == "A" else "2001:db8::30"
    if operation == "create":
        responses = [
            FakeResponse({"DomainRecords": {"Record": []}}),
            FakeResponse({"RecordId": "created"}),
        ]
        expected_action = "AddDomainRecord"
    else:
        responses = [
            FakeResponse(
                {
                    "DomainRecords": {
                        "Record": [
                            {
                                "RecordId": "existing",
                                "RR": "home",
                                "Type": record_type,
                                "Value": "198.51.100.1" if record_type == "A" else "2001:db8::1",
                            }
                        ]
                    }
                }
            ),
            FakeResponse({"RecordId": "existing"}),
        ]
        expected_action = "UpdateDomainRecord"

    session = FakeSession(responses)
    result = AliDnsProvider(session).sync_record(
        case["hostname"], record_type, value, input_ttl, case["credentials"]
    )

    assert result.ok is True
    params = session.calls[1][2]["params"]
    assert params["Action"] == expected_action
    assert params["Type"] == record_type
    assert int(params["TTL"]) == expected_ttl
    assert AliDnsProvider.MIN_TTL <= int(params["TTL"]) <= AliDnsProvider.MAX_TTL


@pytest.mark.parametrize(
    "record_type,operation,input_ttl",
    tuple(itertools.product(RECORD_TYPES, ("create", "update"), (60, 86401))),
)
def test_dnspod_ttl_contract_delegates_to_plan_default(record_type, operation, input_ttl):
    case = CASES["dnspod"]
    value = "198.51.100.30" if record_type == "A" else "2001:db8::30"
    if operation == "create":
        responses = [
            FakeResponse({"Response": {"RecordList": []}}),
            FakeResponse({"Response": {"RecordId": "created"}}),
        ]
        expected_action = "CreateRecord"
    else:
        responses = [
            FakeResponse(
                {
                    "Response": {
                        "RecordList": [
                            {
                                "RecordId": "existing",
                                "Name": "home",
                                "Type": record_type,
                                "Value": "198.51.100.1" if record_type == "A" else "2001:db8::1",
                            }
                        ]
                    }
                }
            ),
            FakeResponse({"Response": {}}),
        ]
        expected_action = "ModifyRecord"

    session = FakeSession(responses)
    result = DnsPodProvider(session).sync_record(
        case["hostname"], record_type, value, input_ttl, case["credentials"]
    )

    assert result.ok is True
    request = session.calls[1][2]
    assert request["headers"]["X-TC-Action"] == expected_action
    assert "TTL" not in request["json"]


@pytest.mark.parametrize("provider_id", ("alidns", "dnspod", "cloudflare"))
def test_record_oriented_noop_contract(provider_id):
    case = CASES[provider_id]
    if provider_id == "alidns":
        responses = [FakeResponse({"DomainRecords": {"Record": [{"RecordId": "1", "RR": "home", "Type": "A", "Value": "198.51.100.30"}]}})]
    elif provider_id == "dnspod":
        responses = [FakeResponse({"Response": {"RecordList": [{"RecordId": "1", "Name": "home", "Type": "A", "Value": "198.51.100.30"}]}})]
    else:
        responses = [FakeResponse({"success": True, "result": [{"id": "1", "name": "home.example.com", "type": "A", "content": "198.51.100.30"}]})]
    result = make_provider(provider_id, responses).sync_record(case["hostname"], "A", "198.51.100.30", 600, case["credentials"])
    assert result.ok is True
    assert result.changed is False


@pytest.mark.parametrize("provider_id", PROVIDER_IDS)
def test_failure_contract_redacts_secret(provider_id):
    case = CASES[provider_id]
    secret = next(value for key, value in case["credentials"].items() if key not in {"zone", "zoneId"})
    result = make_provider(provider_id, case["failure"](secret)).sync_record(case["hostname"], "AAAA", "2001:db8::30", 600, case["credentials"])
    encoded = json.dumps(result.__dict__, ensure_ascii=False)
    assert result.ok is False
    assert result.error_code
    assert secret not in encoded


@pytest.mark.parametrize("provider_id", PROVIDER_IDS)
def test_transport_exception_contract_redacts_secret(provider_id):
    case = CASES[provider_id]
    secret = next(value for key, value in case["credentials"].items() if key not in {"zone", "zoneId"})
    session = RaisingSession(secret)
    result = case["provider"](session).sync_record(case["hostname"], "A", "198.51.100.30", 600, case["credentials"])
    assert result.ok is False
    assert result.error_code == "network_error"
    assert secret not in json.dumps(result.__dict__, ensure_ascii=False)
    assert session.calls == 1


@pytest.mark.parametrize("provider_id,status_code", tuple(itertools.product(PROVIDER_IDS, (401, 403))))
def test_auth_http_status_contract(provider_id, status_code):
    case = CASES[provider_id]
    result = make_provider(provider_id, case["auth"](status_code)).sync_record(case["hostname"], "A", "198.51.100.30", 600, case["credentials"])
    assert result.ok is False
    assert result.error_code in {"http_401", "http_403", "authentication_failed"}


@pytest.mark.parametrize("provider_id", PROVIDER_IDS)
def test_rate_limit_contract_is_retryable(provider_id):
    case = CASES[provider_id]
    provider = make_provider(provider_id, case["rate"]())
    result = provider.sync_record(case["hostname"], "A", "198.51.100.30", 600, case["credentials"])
    assert result.ok is False
    assert result.error_code == "http_429"


@pytest.mark.parametrize("provider_id", PROVIDER_IDS)
def test_public_snapshot_exposes_no_provider_credentials(provider_id):
    case = CASES[provider_id]
    store = LabDdnsStore(Path(tempfile.mkdtemp(prefix="labprobe-ddns-contract-")) / "lab_ddns.json")
    record = store.save_record({"provider": provider_id, "hostname": case["hostname"], "recordTypes": ["A", "AAAA"]})
    store.save_credentials(record["id"], case["credentials"])
    encoded = json.dumps(store.public_snapshot(), ensure_ascii=False)
    for forbidden in ("token", "password", "AccessKeySecret", "SecretKey", "Authorization", "Bearer"):
        assert forbidden not in encoded
    assert store.public_snapshot()["records"][0]["credentialsConfigured"] is True
