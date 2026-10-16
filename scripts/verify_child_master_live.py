import sys,shlex,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"ShinyaHub"/"scripts"))
from deploy_to_nas import NAS_PASS,NAS_USER
from eweb_hub_remote import connect,run
r=Path(__file__).resolve().parents[1]
proof="""import hub,json,time
hub.check_read_token=lambda:True
client=hub.app.test_client()
response=client.get('/api/router/child-guard/master?router=BE72')
body=response.get_json()
print(json.dumps({'status':response.status_code,'masterEnabled':body.get('masterEnabled'),'masterSupported':body.get('masterSupported'),'masterRevision':body.get('masterRevision'),'pending':body.get('pending'),'commandId':body.get('commandId'),'errorCode':body.get('errorCode')}))
assert response.status_code==200 and isinstance(body.get('masterEnabled'),bool), 'Master state not yet confirmed'
with hub.app.test_request_context('/api/router/child-guard/overview?router=BE72'):
    overview=hub._child_guard_overview_payload('BE72')
assert overview.get('masterEnabled')==body['masterEnabled']
print('overview-master-confirmed')
"""
c=connect("36.157.252.49",6011,NAS_USER,NAS_PASS)
try:
    result=run(c,"docker exec labprobe-hub python -c "+shlex.quote(proof),sudo_password=NAS_PASS,timeout=50).decode()
    (r/"test_tmp_child_master_20261016/live-verification.txt").write_text(result)
    print(result)
finally:c.close()
