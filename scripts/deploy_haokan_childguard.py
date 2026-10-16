"""Deploy the reviewed two-file HUB update with exact source checks and rollback."""
from __future__ import annotations

import datetime
import hashlib
import json
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ShinyaHub" / "scripts"))
from deploy_to_nas import NAS_PASS, NAS_USER

from eweb_hub_remote import connect, run


ROOT=Path(__file__).resolve().parents[1]
STAGED=ROOT/'test_tmp_childguard_20261015/live_rdpi/staged'
ORIGINAL={
    'hub.py':'3e46d91b01bfd6fe0791aa28cdf13a2a0d8d29e509ae2959f10b1ef23db4e9c8',
    'rdpi_signature_service.py':'148b6c2bfd569a7f9c197035625fda34e1811f82fb772f6053698ed973231015',
}


def digest(value:bytes)->str:return hashlib.sha256(value).hexdigest()


client=connect('36.157.252.49',6011,NAS_USER,NAS_PASS)
sudo=lambda command,**kwargs:run(client,command,sudo_password=NAS_PASS,**kwargs)
stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
backup='/volume1/docker/labprobe-hub/haokan-backups/'+stamp
started=False
try:
    inspect=json.loads(sudo('docker inspect labprobe-hub'))[0]
    originals={}
    candidates={}
    for name,expected in ORIGINAL.items():
        original=sudo('docker exec labprobe-hub cat /app/'+name)
        if digest(original)!=expected:
            raise RuntimeError('Live '+name+' changed; deployment refused')
        candidate=(STAGED/name).read_bytes()
        compile(candidate,name,'exec')
        originals[name]=original
        candidates[name]=candidate
    sudo('mkdir -p '+shlex.quote(backup))
    sudo('chmod 700 '+shlex.quote(backup))
    for name,data in originals.items():
        sudo('tee '+shlex.quote(backup+'/'+name+'.original'),stdin=data)
    for name,data in candidates.items():
        sudo('tee '+shlex.quote(backup+'/'+name),stdin=data)
    old_image='labprobe-hub:pre-haokan-'+stamp
    sudo('docker tag '+shlex.quote(inspect['Image'])+' '+old_image)
    rollback='#!/bin/sh\nset -eu\n'
    for name in ORIGINAL:
        rollback+='docker cp '+shlex.quote(backup+'/'+name+'.original')+' '+shlex.quote('labprobe-hub:/app/'+name)+'\n'
    rollback+='docker tag '+old_image+' '+shlex.quote(inspect['Config']['Image'])+'\ndocker restart labprobe-hub\n'
    sudo('tee '+shlex.quote(backup+'/rollback.sh'),stdin=rollback.encode())
    sudo('chmod 700 '+shlex.quote(backup+'/rollback.sh'))
    for name in ORIGINAL:
        sudo('docker cp '+shlex.quote(backup+'/'+name)+' '+shlex.quote('labprobe-hub:/app/'+name))
        observed=sudo('docker exec labprobe-hub sha256sum /app/'+name).decode().split()[0]
        if observed!=digest(candidates[name]):raise RuntimeError(name+' checksum mismatch')
    started=True
    sudo('docker restart labprobe-hub',timeout=50)
    proof='''import hub,rdpi_signature_service as svc
assert any(r.rule=="/api/router/rdpi/signatures/haokan" for r in hub.app.url_map.iter_rules())
assert callable(svc.merge_haokan_with_one_empty_slot)
assert hub.app is not None
print("haokan-route-ready")'''
    result=sudo('docker exec labprobe-hub python -c '+shlex.quote(proof),timeout=40)
    if b'haokan-route-ready' not in result:raise RuntimeError('Post-deployment proof missing')
    image='labprobe-hub:haokan-'+stamp
    sudo('docker commit labprobe-hub '+image,timeout=60)
    sudo('docker tag '+image+' '+shlex.quote(inspect['Config']['Image']))
    print(json.dumps({'ok':True,'backup':backup,'hubSha256':digest(candidates['hub.py']),
                      'signatureSha256':digest(candidates['rdpi_signature_service.py'])}))
except Exception:
    if started:
        sudo('sh '+shlex.quote(backup+'/rollback.sh'),timeout=50)
    raise
finally:
    client.close()
