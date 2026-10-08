import json
from pathlib import Path
from types import SimpleNamespace
from flask import Flask
from lab_ddns import install_lab_ddns
from unittest.mock import patch

def client_for(tmp_path: Path, allowed: bool):
    fake = SimpleNamespace(app=Flask('eweb-ddns-credentials'), DATA_DIR=tmp_path, LOGGER=None,
                           check_app_token=lambda: allowed)
    with patch('lab_ddns.LabDdnsStore.start_auto_update'):
        store = install_lab_ddns(fake)
    record = store.save_record({'provider': 'alidns', 'hostname': 'home.example.com', 'recordTypes': ['A']})
    store.secrets.save(record['id'], {'AccessKeyId': 'test-id', 'AccessKeySecret': 'test-only-secret', 'zone': 'example.com'})
    return fake.app.test_client(), record['id']

def test_credentials_read_requires_authorization(tmp_path):
    client, ident = client_for(tmp_path, False)
    response = client.get(f'/api/ddns/{ident}/credentials')
    assert response.status_code == 401
    assert 'test-only-secret' not in response.get_data(as_text=True)

def test_explicit_editor_read_is_not_cached_and_list_remains_redacted(tmp_path):
    client, ident = client_for(tmp_path, True)
    response = client.get(f'/api/ddns/{ident}/credentials')
    assert response.status_code == 200
    assert response.json['credentials']['AccessKeySecret'] == 'test-only-secret'
    assert response.headers['Cache-Control'] == 'no-store'
    assert 'test-only-secret' not in json.dumps(client.get('/api/ddns').json)
    assert client.get('/api/ddns/unknown/credentials').status_code == 404
