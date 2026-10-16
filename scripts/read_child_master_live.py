import sys,shlex,json,hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"ShinyaHub"/"scripts"))
from deploy_to_nas import NAS_PASS,NAS_USER
from eweb_hub_remote import connect,run
root=Path(__file__).resolve().parents[1]/"test_tmp_child_master_20261016"
root.mkdir(exist_ok=True)
c=connect("36.157.252.49",6011,NAS_USER,NAS_PASS)
try:
    sudo=lambda cmd,**kw:run(c,cmd,sudo_password=NAS_PASS,**kw)
    for container in ("labprobe-hub","labprobe-hub-be50"):
        folder=root/container;folder.mkdir(exist_ok=True)
        for name in ("hub.py","usage_aggregate.py","child_guard_service.py"):
            raw=sudo("docker exec "+container+" cat /app/"+name)
            (folder/name).write_bytes(raw)
            print(container,name,hashlib.sha256(raw).hexdigest())
    print(sudo("docker logs --tail 12 labrelay-master-0276").decode())
finally:c.close()
