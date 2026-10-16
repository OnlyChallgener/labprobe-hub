import sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"ShinyaHub"/"scripts"))
from deploy_to_nas import NAS_PASS,NAS_USER
from eweb_hub_remote import connect,run
c=connect("36.157.252.49",6011,NAS_USER,NAS_PASS)
try:
    command="docker inspect labrelay-master-0276 --format '{{.State.Status}} {{.State.ExitCode}}'; docker logs --tail 12 labrelay-master-0276 2>&1; docker top labrelay-master-0276 -eo pid,comm,pcpu,etime || true"
    print(run(c,"sh -c "+__import__('shlex').quote(command),sudo_password=NAS_PASS).decode())
finally:c.close()
