import ast,sys,hashlib,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"ShinyaHub"/"scripts"))
from deploy_to_nas import NAS_PASS,NAS_USER
from eweb_hub_remote import connect,run
r=Path(__file__).resolve().parents[1];out=r/"test_tmp_child_master_20261016";out.mkdir(exist_ok=True)
c=connect("36.157.252.49",6011,NAS_USER,NAS_PASS)
try:
    sudo=lambda cmd,**kw:run(c,cmd,sudo_password=NAS_PASS,**kw)
    proof=sudo("sh -c 'docker inspect labrelay-master-0276 --format \"{{.State.Status}} {{.State.ExitCode}}\"; sha256sum /tmp/labprobe-master-0276/src/child_guard.rs; docker logs labrelay-master-0276 2>&1 | grep -E \"test result:|labrelay 0.2.76\"'")
    print(proof.decode())
    raw=sudo("cat /tmp/labprobe-master-0276/target/aarch64-unknown-linux-musl/release/labrelay")
    (out/"labrelay-linux-arm64").write_bytes(raw)
    print("candidate",len(raw),hashlib.sha256(raw).hexdigest())
finally:c.close()
tree=ast.parse((r.parent/"ShinyaHub/scripts/be72_ssh.py").read_text(encoding="utf-8"))
login=next(n.value for n in ast.walk(tree) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=="connect")
settings={k.arg:ast.literal_eval(k.value) for k in login.keywords if k.arg in {"username","password"}}
c=connect("36.157.252.49",5905,**settings)
try:
    proof=run(c,"uname -m; /usr/bin/labrelay --version; sha256sum /usr/bin/labrelay; jsonfilter -i /etc/labprobe/agent.json -e '@.routerName'").decode()
    (out/"router-preflight.txt").write_text(proof)
    print(proof)
finally:c.close()
