"""Deploy the narrow extension with exact backups and checked live revisions.

Called from a credential-bearing session; this module contains no credentials.
No router or Relay service restart is needed. Hub restart is only for the added
authenticated DDNS editor credential endpoint.
"""
from __future__ import annotations
import datetime
import gzip
import hashlib
import json
import shlex
from pathlib import Path
from eweb_hub_remote import connect, run, read, write
from patch_be72_eweb_hub import APP_NAME, APP_HASH, build

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'build_artifacts/oct08-eweb-hub-plan'
OUTPUT = SOURCE / 'candidate'
STATIC = '/www/luci-static/eweb-ehr-exp/static/'
CACHES = ['/tmp/luci-indexcache', '/tmp/luci-modulecache/6C7563692E636F6E74726F6C6C65722E657765622E617069',
          '/tmp/luci-modulecache/6C7563692E6D6F64756C65732E6C616270726F6265']
DDNS_LIVE_HASH = '8ef43ec1c0f1031ee7ba7a869a948c0e2f012d1a2654d711407582a031e8de4c'

def digest(value):
    return hashlib.sha256(value).hexdigest()

def deploy(router, nas, nas_password):
    manifest = build(SOURCE, OUTPUT)
    agent = json.loads(read(router, '/etc/labprobe/agent.json'))
    if agent.get('routerName') != 'BE72' or agent.get('hubUrl') != 'http://192.168.5.46:58443':
        raise RuntimeError('Router/Hub binding changed; refuse deployment')
    live_app = read(router, STATIC + 'js/' + APP_NAME + '.gz')
    if digest(gzip.decompress(live_app)) != APP_HASH:
        raise RuntimeError('Live eWeb app hash changed')
    live_api = read(router, '/usr/lib/lua/luci/controller/eweb/api.lua')
    if live_api != (SOURCE / 'router-source/api.lua').read_bytes():
        raise RuntimeError('Live native API changed')

    sudo = lambda cmd, **kwargs: run(nas, cmd, sudo_password=nas_password, **kwargs)
    inspection = json.loads(sudo('docker inspect labprobe-hub'))[0]
    token = next((row.split('=', 1)[1] for row in inspection['Config']['Env'] if row.startswith('APP_TOKEN=')), '')
    if not token or any(c in token for c in '\r\n"\\'):
        raise RuntimeError('Hub app credential unavailable/invalid')
    curl_config = ('header = "Authorization: Bearer ' + token + '"\nheader = "Content-Type: application/json"\nnoproxy = "*"\n').encode()
    native_config = json.dumps({'routerName': agent['routerName'], 'hubUrl': agent['hubUrl']}).encode()
    # Verify the BE72 endpoint before committing files. Never emit the secret.
    status = json.loads(run(router, 'curl --silent --max-time 8 --config - --url ' + shlex.quote(agent['hubUrl'] + '/api/wireguard/server'), stdin=curl_config))
    if not status.get('ok') or status.get('agentStatus', {}).get('router') != 'BE72':
        raise RuntimeError('Hub returned a different router identity')

    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup = '/etc/labprobe/backups/eweb-hub-' + stamp
    run(router, 'mkdir -p ' + shlex.quote(backup) + ' ' + shlex.quote(STATIC + 'labprobe') + ' && chmod 700 ' + shlex.quote(backup))
    files = [('/usr/lib/lua/luci/modules/labprobe.lua', (OUTPUT / 'labprobe.lua').read_bytes(), '644'),
             ('/etc/labprobe/eweb-hub.json', native_config, '600'),
             ('/etc/labprobe/eweb-hub.curl', curl_config, '600')]
    for name in ['hub-pages.js', 'hub-pages.css', 'hub-pages.js.gz', 'hub-pages.css.gz']:
        files.append((STATIC + 'labprobe/' + name, (OUTPUT / name).read_bytes(), '644'))
    files.extend([('/usr/lib/lua/luci/controller/eweb/api.lua', (OUTPUT / 'api.lua').read_bytes(), '644'),
                  (STATIC + 'js/' + APP_NAME + '.gz', (OUTPUT / (APP_NAME + '.gz')).read_bytes(), '644')])
    rollback = ['#!/bin/sh', 'set -eu']
    staged = []
    for index, (path, data, mode) in enumerate(files):
        exists = run(router, 'if [ -f ' + shlex.quote(path) + ' ]; then echo yes; fi').strip() == b'yes'
        old = backup + '/original-' + str(index)
        if exists:
            run(router, 'cp -p ' + shlex.quote(path) + ' ' + shlex.quote(old))
            rollback.append('cp -p ' + shlex.quote(old) + ' ' + shlex.quote(path))
        else:
            rollback.append('rm -f ' + shlex.quote(path))
        candidate = backup + '/candidate-' + str(index)
        write(router, candidate, data, mode)
        staged.append((candidate, path, mode, digest(data)))
    rollback.append('rm -f ' + ' '.join(map(shlex.quote, CACHES)))
    write(router, backup + '/rollback.sh', ('\n'.join(rollback) + '\n').encode(), '700')
    for index in [0, len(files)-2]:
        run(router, 'lua -e ' + shlex.quote('assert(loadfile("' + staged[index][0] + '"))'))

    # Patch only the endpoint in the live module; reject an unrecognized version.
    original_ddns = sudo('docker exec labprobe-hub cat /app/lab_ddns.py')
    if digest(original_ddns) != DDNS_LIVE_HASH:
        raise RuntimeError('Live DDNS module changed; refuse replacement')
    source = (ROOT / 'lab_ddns.py').read_bytes()
    start = source.index(b'    @blueprint.get("/<record_id>/credentials")')
    end = source.index(b'    @blueprint.post("")', start)
    anchor = b'    @blueprint.post("")'
    if original_ddns.count(anchor) != 1:
        raise RuntimeError('DDNS endpoint anchor missing')
    ddns_candidate = original_ddns.replace(anchor, source[start:end] + anchor, 1)
    host_backup = '/volume1/docker/labprobe-hub/eweb-backups/' + stamp
    sudo('mkdir -p ' + shlex.quote(host_backup))
    sudo('chmod 700 ' + shlex.quote(host_backup))
    sudo('tee ' + shlex.quote(host_backup + '/lab_ddns.original.py'), stdin=original_ddns)
    sudo('tee ' + shlex.quote(host_backup + '/lab_ddns.py'), stdin=ddns_candidate)
    sudo('docker exec labprobe-hub cp -p /app/lab_ddns.py /app/lab_ddns.pre-eweb-hub.py')
    sudo('docker cp ' + shlex.quote(host_backup + '/lab_ddns.py') + ' labprobe-hub:/app/lab_ddns.py')
    sudo('docker exec labprobe-hub python -c ' + shlex.quote('compile(open("/app/lab_ddns.py").read(),"lab_ddns.py","exec")'))
    # Preserve a recoverable image before advancing the existing deployment tag.
    image = inspection['Config']['Image']
    image_backup = 'labprobe-hub:eweb-hub-original-' + stamp
    sudo('docker tag ' + shlex.quote(inspection['Image']) + ' ' + image_backup)
    image_candidate = 'labprobe-hub:oct08-be72-eweb-hub'
    sudo('docker commit labprobe-hub ' + image_candidate, timeout=55)
    sudo('docker tag ' + image_candidate + ' ' + shlex.quote(image))
    sudo('docker restart labprobe-hub', timeout=35)
    nas_rollback = '#!/bin/sh\nset -eu\ndocker cp ' + shlex.quote(host_backup + '/lab_ddns.original.py') + ' labprobe-hub:/app/lab_ddns.py\ndocker tag ' + image_backup + ' ' + shlex.quote(image) + '\ndocker restart labprobe-hub\n'
    sudo('tee ' + shlex.quote(host_backup + '/rollback.sh'), stdin=nas_rollback.encode())
    sudo('chmod 700 ' + shlex.quote(host_backup + '/rollback.sh'))
    try:
        for candidate, target, mode, expected in staged:
            run(router, 'cp ' + shlex.quote(candidate) + ' ' + shlex.quote(target) + ' && chmod ' + mode + ' ' + shlex.quote(target))
            if digest(read(router, target)) != expected:
                raise RuntimeError('Deployment hash mismatch')
        run(router, 'rm -f ' + ' '.join(map(shlex.quote, CACHES)))
    except Exception:
        run(router, 'sh ' + shlex.quote(backup + '/rollback.sh'))
        sudo('sh ' + shlex.quote(host_backup + '/rollback.sh'), timeout=35)
        raise
    proof = {'version': manifest['version'], 'router': 'BE72', 'routerBackup': backup, 'nasBackup': host_backup,
             'candidateHashes': {name: value for name, value in manifest['files'].items()}, 'hubModuleHash': digest(ddns_candidate)}
    (OUTPUT / 'deployment.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
    return proof
