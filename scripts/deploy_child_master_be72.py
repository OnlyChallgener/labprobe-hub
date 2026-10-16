import ast,sys,hashlib,json,datetime,shlex
from pathlib import Path
from eweb_hub_remote import connect,run,write
r=Path(__file__).resolve().parents[1];out=r/"test_tmp_child_master_20261016"
raw=(out/"labrelay-linux-arm64").read_bytes();digest=hashlib.sha256(raw).hexdigest()
assert digest=="a769a75c58915f463a85e9f3fa353a6ec00d534a18d85b3f6ff49f6faf9c2acd"
tree=ast.parse((r.parent/"ShinyaHub/scripts/be72_ssh.py").read_text(encoding="utf-8"))
login=next(n.value for n in ast.walk(tree) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=="connect")
settings={k.arg:ast.literal_eval(k.value) for k in login.keywords if k.arg in {"username","password"}}
c=connect("36.157.252.49",5905,**settings)
try:
    write(c,"/tmp/labrelay-0.2.76-candidate",raw,"755")
    source=(r/"build_artifacts/oct07-relay-0274/deploy-be72.sh").read_text()
    source=source.replace("0.2.74","0.2.76").replace("0.2.73","0.2.75")
    source=source.replace("ce152b996cc67374fb209e99f9b4d3478d950f292a04e89ed2a3634763d83bbe",digest)
    source=source.replace("af01229e9338900f4a9e74a1fa86e8174387e6086c2c815b2c7b7a88ff126a41","675f38b624db7a68949d8a7ff31f6e4f92cb1ee943e0c15b6b4cba794050f612")
    write(c,"/tmp/deploy-child-master-0276.sh",source.encode(),"700")
    print(run(c,"sh /tmp/deploy-child-master-0276.sh --preflight").decode())
    proof=run(c,"sh /tmp/deploy-child-master-0276.sh --switch",timeout=45).decode()
    (out/"be72-deployment.txt").write_text(proof)
    print(proof)
finally:c.close()
