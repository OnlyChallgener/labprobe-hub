import gzip

import pytest
from flask import Flask, Response, jsonify

from http_response_compression import install_json_compression


@pytest.fixture
def client():
    app = Flask(__name__)
    install_json_compression(app)
    install_json_compression(app)

    @app.get('/api/sync/snapshot')
    def snapshot():
        return jsonify(events=[{'id': i, 'text': '设备状态更新' * 8} for i in range(400)])

    @app.get('/api/router/config')
    def config():
        return jsonify(secret='secret' * 1000)

    @app.get('/api/events')
    def stream():
        return Response(iter(['{"events":[]}' * 500]), mimetype='application/json')

    return app.test_client()


def test_large_snapshot_roundtrips_every_event_and_revision(client):
    plain = client.get('/api/sync/snapshot')
    compressed = client.get('/api/sync/snapshot', headers={'Accept-Encoding': 'gzip'})
    assert gzip.decompress(compressed.data) == plain.data
    assert len(compressed.data) < len(plain.data) / 5
    assert compressed.headers['Content-Length'] == str(len(compressed.data))
    assert 'Accept-Encoding' in compressed.headers['Vary']


@pytest.mark.parametrize('encoding', ['', 'identity', 'gzip;q=0, br', 'gzip;q=0, *;q=1'])
def test_respects_clients_that_do_not_accept_gzip(client, encoding):
    result = client.get('/api/sync/snapshot', headers={'Accept-Encoding': encoding})
    assert 'Content-Encoding' not in result.headers
    assert len(result.json['events']) == 400


def test_does_not_compress_stream_or_credentials(client):
    for path in ('/api/events', '/api/router/config'):
        assert 'Content-Encoding' not in client.get(path, headers={'Accept-Encoding': 'gzip'}).headers
