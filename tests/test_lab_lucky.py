import concurrent.futures
import copy
import json
from unittest.mock import patch

import pytest
from flask import Flask

from lab_lucky import LuckyClient, LuckyError, LuckyStore, endpoint, register_lucky, rule_fields


@pytest.fixture
def child_api(tmp_path):
    app = Flask(__name__)
    register_lucky(app, tmp_path, lambda: True)
    with patch.object(LuckyClient, 'call', return_value={'ruleList': [], 'list': []}):
        key = LuckyStore(tmp_path).save({'url': 'http://localhost', 'name': 'test', 'token': 'secret'})
    parent = {'RuleKey': 'r', 'RuleName': 'group', 'Enable': True, 'Future': 'preserve', 'ProxyList': [
        {'Key': sid, 'Remark': sid, 'Enable': True, 'Domains': [sid + '.example.com'],
         'Locations': ['http://localhost:80'], 'WebServiceType': 'reverseproxy',
         'OtherParams': {'Password': 'PRIVATE'}, 'FutureChild': {'keep': True}} for sid in ('a', 'b')]}
    state = {'version': 7, 'subversion': 3, 'writes': []}
    def upstream(self, method, path, body=None):
        if method == 'GET' and path.endswith('/edit-snapshot'):
            sid = path.split('/')[-2]
            sub = next(s for s in parent['ProxyList'] if s['Key'] == sid)
            return {'snapshot': {'RuleKey': 'r', 'Version': state['subversion'], 'SubRule': copy.deepcopy(sub)}}
        if method == 'GET':
            return {'rule': copy.deepcopy(parent), 'version': state['version']}
        state['writes'].append(copy.deepcopy(body))
        if path.endswith('/config'):
            sid = path.split('/')[-2]
            parent['ProxyList'] = [copy.deepcopy(body['SubRule']) if s['Key'] == sid else s for s in parent['ProxyList']]
            state['subversion'] += 1
        else:
            assert body['ExpectedVersion'] == state['version']
            parent.update({k: copy.deepcopy(v) for k, v in body.items() if k != 'ExpectedVersion'})
        state['version'] += 1
        return {'ret': 0}
    with patch.object(LuckyClient, 'call', upstream):
        yield app.test_client(), f'/api/lucky/{key}/rules/r/subrules/', parent, state


def test_subrule_edit_uses_own_version_preserves_peer_and_private_fields(child_api):
    client, path, parent, state = child_api
    peer = copy.deepcopy(parent['ProxyList'][1])
    detail = client.get(path + 'a')
    assert detail.status_code == 200 and detail.json['item']['editable']
    assert 'PRIVATE' not in detail.text and 'OtherParams' not in detail.text
    assert client.put(path + 'a', json={'version': 2, 'enabled': False}).status_code == 409
    assert not state['writes']
    response = client.put(path + 'a', json={'version': 3, 'name': 'updated', 'domains': ['new.example.com', 'alias.example.com'], 'backends': ['http://localhost:81/path?q=1']})
    assert response.status_code == 200
    assert parent['ProxyList'][1] == peer
    assert parent['ProxyList'][0]['OtherParams'] == {'Password': 'PRIVATE'}
    assert parent['ProxyList'][0]['FutureChild'] == {'keep': True}
    assert parent['Future'] == 'preserve'
    assert response.json['version'] == 4 and response.json['ruleVersion'] == 8
    assert 'PRIVATE' not in response.text


def test_subrule_toggle_and_delete_preserve_siblings_and_parent(child_api):
    client, path, parent, state = child_api
    peer = copy.deepcopy(parent['ProxyList'][1])
    assert client.put(path + 'a', json={'version': 3, 'enabled': False}).status_code == 200
    assert parent['ProxyList'][0]['Enable'] is False and parent['ProxyList'][1] == peer
    assert client.delete(path + 'a', json={'ruleVersion': 7}).status_code == 409
    assert len(state['writes']) == 1
    assert client.delete(path + 'a', json={'ruleVersion': 8}).status_code == 200
    assert parent['ProxyList'] == [peer] and parent['Enable'] is True
    assert state['writes'][-1]['ExpectedVersion'] == 8
    assert client.get(path + 'a').status_code == 404


def test_subrule_invalid_fields_or_wrong_parent_never_write(child_api):
    client, path, parent, state = child_api
    assert client.get(path + 'missing').status_code == 404
    assert client.put(path + 'a', json={'version': 3, 'enabled': 'false'}).status_code == 400
    assert client.put(path + 'a', json={'version': 3, 'domains': [], 'backends': ['http://localhost']}).status_code == 400
    parent['ProxyList'][0]['WebServiceType'] = 'fileserver'
    assert client.get(path + 'a').json['item']['editable'] is False
    assert client.put(path + 'a', json={'version': 3, 'domains': ['nas.example.com'], 'backends': ['http://localhost']}).status_code == 400
    parent['ProxyList'][0]['WebServiceType'] = 'reverseproxy'
    parent['ProxyList'][0]['OtherParams']['BackendPool'] = {'schemaVersion': 1, 'Nodes': []}
    assert client.get(path + 'a').json['item']['editable'] is False
    assert client.put(path + 'a', json={'version': 3, 'domains': ['nas.example.com'], 'backends': ['http://localhost']}).status_code == 400
    assert not state['writes']


def test_address_security_entry_is_not_router_channel():
    assert endpoint('http://127.0.0.1:16601/BE72/') == 'http://127.0.0.1:16601/BE72'
    for value in ('file:///etc/passwd', 'https://a:70000', 'http://user:pass@a', 'https://a?token=x'):
        with pytest.raises((LuckyError, ValueError)):
            endpoint(value)


@pytest.mark.parametrize('port', [0, 70000, True, 1.2, '1.2', -1])
def test_invalid_ports_rejected_before_upstream(port):
    with pytest.raises(LuckyError):
        rule_fields(dict(name='NAS', domain='nas.example.com', backend='http://127.0.0.1:80', port=port))


def test_durable_uncertain_operation_never_replayed(tmp_path):
    s = LuckyStore(tmp_path)
    calls = []
    def failed():
        calls.append(1)
        raise TimeoutError()
    with pytest.raises(TimeoutError):
        s.once('operation-123456789', {'create': 1}, failed)
    with pytest.raises(LuckyError):
        LuckyStore(tmp_path).once('operation-123456789', {'create': 1}, failed)
    assert len(calls) == 1


def test_shared_worker_key_publication(tmp_path):
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        stores = list(pool.map(lambda _: LuckyStore(tmp_path), range(4)))
    secret = stores[0].cipher.encrypt(b'secret')
    assert all(s.cipher.decrypt(secret) == b'secret' for s in stores)


def test_update_preserves_unknowns_and_rejects_stale_version(tmp_path):
    app = Flask(__name__)
    register_lucky(app, tmp_path, lambda: True)
    store = LuckyStore(tmp_path)
    with patch.object(LuckyClient, 'call', return_value={'ruleList': [], 'list': []}):
        key = store.save({'url': 'http://localhost', 'name': 'test', 'token': 'secret'})
    raw = {'RuleKey': 'r', 'RuleName': 'old', 'Enable': True, 'UnknownFutureField': {'secret': 'keep'},
           'ProxyList': [{'Domains': ['nas.example.com'], 'Locations': ['http://localhost'], 'WebServiceType': 'reverseproxy', 'OtherParams': {'auth': 'keep'}}]}
    writes = []
    def call(self, method, path, body=None):
        if method == 'GET':
            return {'rule': raw.copy(), 'version': 2}
        writes.append(body.copy()); raw.update(body)
        return {'ret': 0}
    with patch.object(LuckyClient, 'call', call), patch.object(LuckyClient, 'rules', return_value=[{'id': 'r', 'editable': True}]):
        c = app.test_client()
        assert c.put(f'/api/lucky/{key}/rules/r', json={'version': 1, 'enabled': False}).status_code == 409
        assert not writes
        assert c.put(f'/api/lucky/{key}/rules/r', json={'version': 2, 'name': 'new', 'domain': 'new.example.com', 'backend': 'http://localhost:80/path?q=1', 'port': 8080}).status_code == 200
    assert writes[0]['UnknownFutureField'] == {'secret': 'keep'}
    assert writes[0]['ProxyList'][0]['OtherParams'] == {'auth': 'keep'}
    assert writes[0]['ExpectedVersion'] == 2


def test_certificates_and_connection_dtos_never_expose_credentials(tmp_path):
    app = Flask(__name__)
    register_lucky(app, tmp_path, lambda: True)
    store = LuckyStore(tmp_path)
    with patch.object(LuckyClient, 'call', return_value={'ruleList': [], 'list': []}):
        key = store.save({'url': 'http://localhost', 'name': 'test', 'token': 'open-token-secret'})
    raw = [{'Key': 'c', 'Remark': 'NAS', 'Enable': True, 'AddFrom': 'acme', 'KeyBase64': 'PRIVATE-KEY', 'ExtParams': {'acmeDNSServer': 'alidns', 'acmeDNSSecret': 'DNS-SECRET', 'acmeDomains': ['nas.example.com']}}]
    with patch.object(LuckyClient, 'certificates', return_value=raw):
        text = app.test_client().get(f'/api/lucky/{key}/certificates').text + app.test_client().get('/api/lucky/connections').text
    assert all(s not in text for s in ('PRIVATE-KEY', 'DNS-SECRET', 'open-token-secret', 'ExtParams', 'secret'))
    assert b'open-token-secret' not in store.path.read_bytes()


def test_module_startup_and_business_auth_are_not_empty_success():
    class Response:
        status_code = 503
        ok = False
        def json(self): return {'ret': -10}
    with patch('lab_lucky.requests.request', return_value=Response()):
        with pytest.raises(LuckyError) as e:
            LuckyClient('http://localhost', 'token').rules()
    assert e.value.status == 503


@pytest.mark.parametrize('transport_error, label', [
    (__import__('requests').exceptions.SSLError('untrusted certificate'), '证书校验失败'),
    (__import__('requests').exceptions.Timeout('timeout'), '超时'),
])
def test_connection_errors_are_actionable_without_exposing_tokens(transport_error, label):
    with patch('lab_lucky.requests.request', side_effect=transport_error), pytest.raises(LuckyError) as e:
        LuckyClient('https://localhost:1661/be72', 'PRIVATE-TOKEN').rules()
    assert label in str(e.value)
    assert 'PRIVATE-TOKEN' not in str(e.value)


def test_app_auth_required(tmp_path):
    app = Flask(__name__)
    register_lucky(app, tmp_path, lambda: False)
    assert app.test_client().get('/api/lucky/connections').status_code == 401


def test_rule_dto_preserves_subrule_associations_instead_of_parallel_flat_lists():
    raw = {'ret': 0, 'ruleList': [{'RuleKey': 'r', 'ProxyList': [
        {'Key': 'a', 'Domains': ['ug.example.com'], 'Locations': ['https://192.168.5.44:9443'], 'OtherParams': {'Password': 'SECRET'}},
        {'Key': 'b', 'Domains': ['fs.example.com'], 'Locations': ['http://192.168.5.152:12769']},
    ]}]}
    client = LuckyClient('http://localhost', 'token')
    with patch.object(client, 'call', return_value=raw):
        row = client.rules()[0]
    assert row['routes'][0]['domains'] == ['ug.example.com']
    assert row['routes'][0]['backends'] == ['https://192.168.5.44:9443']
    assert row['routes'][1]['domains'] == ['fs.example.com']
    assert row['routes'][1]['backends'] == ['http://192.168.5.152:12769']
    assert 'SECRET' not in json.dumps(row)


def test_null_empty_go_slices_are_distinct_from_missing_or_invalid_payload():
    client = LuckyClient('http://localhost', 'token')
    with patch.object(client, 'call', return_value={'ruleList': None}):
        assert client.rules() == []
    with patch.object(client, 'call', return_value={'list': None}):
        assert client.certificates() == []
    for payload in ({}, {'ruleList': 'not-a-list'}):
        with patch.object(client, 'call', return_value=payload), pytest.raises(LuckyError):
            client.rules()


def test_certificate_application_reuses_credentials_only_inside_hub(tmp_path):
    app = Flask(__name__)
    register_lucky(app, tmp_path, lambda: True)
    store = LuckyStore(tmp_path)
    with patch.object(LuckyClient, 'call', return_value={'ruleList': [], 'list': []}):
        key = store.save({'url': 'http://localhost', 'name': 'test', 'token': 'secret'})
    raw = [{'Key': 'source', 'Remark': 'DNS', 'AddFrom': 'acme', 'ExtParams': {'acmeDNSServer': 'alidns', 'acmeDNSID': 'ID', 'acmeDNSSecret': 'PRIVATE', 'acmeDomains': ['old.example.com'], 'acmeKid': 'old-account', 'acmeUseGlobalPrivateKey': True}}]
    sent = []
    def upstream(self, method, path, body=None):
        sent.append(body)
        raw.append(dict(body, Key='new'))
        return {'ret': 0, 'key': 'new'}
    with patch.object(LuckyClient, 'certificates', side_effect=lambda: raw), patch.object(LuckyClient, 'call', upstream):
        c = app.test_client()
        body = {'accountId': 'source', 'domains': 'new.example.com', 'operationId': 'certificate-1234567890'}
        r = c.post(f'/api/lucky/{key}/certificates', json=body)
        assert r.status_code == 200
        assert 'PRIVATE' not in r.text and 'old-account' not in r.text
        assert c.post(f'/api/lucky/{key}/certificates', json=body).status_code == 200
        assert len(sent) == 1
    assert sent[0]['Enable'] is True
    assert sent[0]['ExtParams']['acmeDNSSecret'] == 'PRIVATE'
    assert sent[0]['ExtParams']['acmeKid'] == ''
    assert sent[0]['ExtParams']['acmeUseGlobalPrivateKey'] is False
    assert sent[0]['ExtParams']['acmeDomains'] == ['new.example.com']
