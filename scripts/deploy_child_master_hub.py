import sys,hashlib,json,datetime,shlex
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"ShinyaHub"/"scripts"))
from deploy_to_nas import NAS_PASS,NAS_USER
from eweb_hub_remote import connect,run
r=Path(__file__).resolve().parents[1];folder=r/"test_tmp_child_master_20261016/labprobe-hub"
names=("hub.py","usage_aggregate.py","child_guard_service.py")
digest=lambda raw:hashlib.sha256(raw).hexdigest()
c=connect("36.157.252.49",6011,NAS_USER,NAS_PASS)
sudo=lambda cmd,**kw:run(c,cmd,sudo_password=NAS_PASS,**kw)
backup="/volume1/docker/labprobe-hub/master-backups/"+datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
changed=False
try:
    info=json.loads(sudo("docker inspect labprobe-hub"))[0]
    originals={};candidates={}
    for name in names:
        old=sudo("docker exec labprobe-hub cat /app/"+name)
        if digest(old)!=digest((folder/name).read_bytes()): raise RuntimeError("Live source changed: "+name)
        candidate=(folder/"staged"/name).read_bytes();compile(candidate,name,"exec")
        originals[name]=old;candidates[name]=candidate
    sudo("mkdir -p "+backup);sudo("chmod 700 "+backup)
    for name in names:
        sudo("tee "+backup+"/"+name+".original",stdin=originals[name])
        sudo("tee "+backup+"/"+name,stdin=candidates[name])
    oldtag="labprobe-hub:pre-master-"+datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    sudo("docker tag "+info["Image"]+" "+oldtag)
    changed=True
    for name in names:
        sudo("docker cp "+backup+"/"+name+" labprobe-hub:/app/"+name)
    sudo("docker restart labprobe-hub",timeout=50)
    proof='import hub; assert any(r.rule=="/api/router/child-guard/master" for r in hub.app.url_map.iter_rules()); print("master-route-ready")'
    print(sudo("docker exec labprobe-hub python -c "+shlex.quote(proof),timeout=40).decode())
    tag="labprobe-hub:master-"+datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    sudo("docker commit labprobe-hub "+tag,timeout=60)
    sudo("docker tag "+tag+" "+shlex.quote(info["Config"]["Image"]))
    record={"ok":True,"backup":backup,"oldImage":oldtag,"image":tag,"hashes":{name:digest(raw) for name,raw in candidates.items()}}
    (folder.parent/"hub-deployment.json").write_text(json.dumps(record,indent=2))
    print(json.dumps(record))
except Exception:
    if changed:
        for name in names: sudo("docker cp "+backup+"/"+name+".original labprobe-hub:/app/"+name)
        sudo("docker tag "+oldtag+" "+shlex.quote(info["Config"]["Image"]))
        sudo("docker restart labprobe-hub",timeout=50)
    raise
finally:c.close()
