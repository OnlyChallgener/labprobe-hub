"""Validate then apply one HaoKan rule through the live authenticated HUB API."""
import base64
import json
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ShinyaHub" / "scripts"))
from deploy_to_nas import NAS_PASS,NAS_USER
from eweb_hub_remote import connect,run

remote='''import json,requests
import hub
from rdpi_signature_service import merge_haokan_with_one_empty_slot
snapshot=hub._rdpi_router_snapshot()
assert snapshot and snapshot.get('dbText'), 'Router library snapshot unavailable'
db=json.loads(snapshot['dbText'])
candidate,expected=merge_haokan_with_one_empty_slot(db)
print('dry-run '+json.dumps({'before':len(db.get('apps',[])),
      'after':len(candidate.get('apps',[])) if candidate else len(db.get('apps',[])),
      'retiredEmptySlot':expected.get('retiredEmptySlot'),'index':'9-234-1-0'}))
if candidate is None:
    print('already-installed')
else:
    session=requests.Session();session.trust_env=False
    response=session.post('http://127.0.0.1:'+str(hub.PORT)+'/api/router/rdpi/signatures/haokan',
        headers={'Authorization':'Bearer '+hub.get_app_token()},json={},timeout=85)
    result=response.json()
    print('apply '+json.dumps({'http':response.status_code,'ok':result.get('ok'),
        'pending':result.get('pending'),'retiredEmptySlot':result.get('retiredEmptySlot'),
        'errorCode':result.get('errorCode'),'message':result.get('message')}))
    if response.status_code!=200 or not result.get('ok'):
        raise RuntimeError('HaoKan write did not finish successfully')
'''
encoded=base64.b64encode(remote.encode()).decode()
command='docker exec labprobe-hub python -c '+shlex.quote('import base64;exec(base64.b64decode("'+encoded+'"))')
client=connect('36.157.252.49',6011,NAS_USER,NAS_PASS)
try:
    print(run(client,command,sudo_password=NAS_PASS,timeout=110).decode('utf-8','replace').strip())
finally:client.close()
