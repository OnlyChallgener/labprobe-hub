import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"ShinyaHub"/"scripts"))
from deploy_to_nas import NAS_PASS,NAS_USER
from eweb_hub_remote import connect,run
r=Path(__file__).resolve().parents[1]
c=connect("36.157.252.49",6011,NAS_USER,NAS_PASS)
try:
    run(c,"tee /tmp/labprobe-master-0276/src/child_guard.rs",stdin=(r/"labrelay/src/child_guard.rs").read_bytes(),sudo_password=NAS_PASS)
    print("Updated master candidate source")
finally:c.close()
