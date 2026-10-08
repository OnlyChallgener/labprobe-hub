"""Deploy only the compatibility module and its small entrypoint hook.

Credentials are supplied by the calling session, never stored by this script.
The original image and exact live files are backed up before the Hub restart.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import shlex
import time
from pathlib import Path

from eweb_hub_remote import connect, run

ROOT = Path(__file__).resolve().parents[1]


def deploy(host, port, username, password, container="labprobe-hub"):
    client = connect(host, port, username, password)
    sudo = lambda command, **kwargs: run(client, command, sudo_password=password, **kwargs)
    inspection = json.loads(sudo("docker inspect " + shlex.quote(container)))[0]
    original = sudo("docker exec " + shlex.quote(container) + " cat /app/hub_entry.py")
    anchor = b"hub.ROUTER_SERVICE = router_service"
    hook = b"\n\nfrom shinya_compat import install_shinya_compat\ninstall_shinya_compat(hub)"
    if original.count(anchor) != 1 or b"install_shinya_compat(hub)" in original:
        raise RuntimeError("Live entrypoint changed or adapter already installed")
    candidate = original.replace(anchor, anchor + hook, 1)
    source = (ROOT / "shinya_compat.py").read_bytes()
    compile(source, "shinya_compat.py", "exec")
    compile(candidate, "hub_entry.py", "exec")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = "/volume1/docker/labprobe-hub/shinya-backups/" + stamp
    sudo("mkdir -p " + shlex.quote(backup))
    sudo("chmod 700 " + shlex.quote(backup))
    for name, data in (("hub_entry.original.py", original), ("hub_entry.py", candidate), ("shinya_compat.py", source)):
        sudo("tee " + shlex.quote(backup + "/" + name), stdin=data)
    image = inspection["Config"]["Image"]
    old_image = "labprobe-hub:pre-shinya-" + stamp
    sudo("docker tag " + shlex.quote(inspection["Image"]) + " " + old_image)
    rollback = ("#!/bin/sh\nset -eu\ndocker cp " + shlex.quote(backup + "/hub_entry.original.py")
                + " " + shlex.quote(container + ":/app/hub_entry.py") + "\ndocker tag "
                + old_image + " " + shlex.quote(image) + "\ndocker restart " + shlex.quote(container) + "\n")
    sudo("tee " + shlex.quote(backup + "/rollback.sh"), stdin=rollback.encode())
    sudo("chmod 700 " + shlex.quote(backup + "/rollback.sh"))
    started = False
    try:
        for name in ("shinya_compat.py", "hub_entry.py"):
            sudo("docker cp " + shlex.quote(backup + "/" + name) + " " + shlex.quote(container + ":/app/" + name))
        sudo("docker exec " + shlex.quote(container) + " python -c " + shlex.quote(
            'compile(open("/app/hub_entry.py").read(),"hub_entry.py","exec");'
            'compile(open("/app/shinya_compat.py").read(),"shinya_compat.py","exec")'))
        started = True
        sudo("docker restart " + shlex.quote(container), timeout=40)
        probe = r'''
import json, os, requests
base="http://127.0.0.1:" + os.environ.get("PORT", "8080")
# Discover the bound port from the Hub configuration when PORT is not exported.
import hub
port=hub.cfg_get("server.port", 58443)
base="http://127.0.0.1:" + str(os.environ.get("PORT") or port)
token=hub.get_app_token()
session=requests.Session()
session.trust_env=False
headers={"Authorization":"Bearer " + token}
def post(path, body=None, auth=True):
    return session.post(base+path,json=body or {},headers=headers if auth else {},timeout=20).json()
login=post("/api/v1/base/homeUser/accountPasswordLogin",{"password":token},False)
assert login["code"] == 0 and login["data"]["token"] == token
assert post("/api/v1/base/homeUser/accountPasswordLogin",{"password":"invalid"},False)["code"] == 401
projects=post("/homewlan/apMonitor/getProjectList2")
assert projects["code"] == 0
project=projects["data"]["dataList"][0]
aps=post("/homewlan/homeAp/getDeviceInfoList2",{"projectId":project["buildingId"]})
devices=post("/homewlan/homeAp/getStaList2",{"projectId":project["buildingId"]})
assert aps["code"] == devices["code"] == 0
assert post("/homewlan/homeAp/setWifiNameAndPasscode2")["code"] == 501
assert post("/homewlan/homeAp/getStaList2",{"projectId":"hub:other"})["code"] == 404
native=session.get(base+"/api/router/devices",headers=headers,timeout=20).json()
assert len(native) == len(devices["data"]["sta_list"])
print("SHINYA_PROOF=" + json.dumps({"ok":True,"router":project["name"],"mainAp":aps["data"]["mainAp"],
                  "temperature":aps["data"]["apList"][0].get("temperature"),
                  "deviceCount":len(native),"login":True,"routerIsolation":True,
                  "unsupportedWritesRejected":True},ensure_ascii=False))
'''
        proof = None
        last_error = None
        for attempt in range(15):
            try:
                output = sudo("docker exec " + shlex.quote(container) + " python -c " + shlex.quote(probe), timeout=35)
                records = [line.partition(b"=")[2] for line in output.splitlines()
                           if line.startswith(b"SHINYA_PROOF=")]
                if len(records) != 1:
                    raise RuntimeError("Verification record missing or ambiguous")
                proof = json.loads(records[0])
                break
            except Exception as error:
                last_error = error
                time.sleep(2)
        if proof is None:
            raise RuntimeError("Post-deployment verification failed") from last_error
        new_image = "labprobe-hub:shinya-compat-" + stamp
        sudo("docker commit " + shlex.quote(container) + " " + new_image, timeout=55)
        sudo("docker tag " + new_image + " " + shlex.quote(image))
        proof.update({"backup": backup, "image": new_image,
                      "moduleSha256": hashlib.sha256(source).hexdigest()})
        destination = ROOT / "build_artifacts/shinya-hub-20261008"
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "deployment.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(proof, ensure_ascii=False))
        return proof
    except Exception:
        if started:
            sudo("sh " + shlex.quote(backup + "/rollback.sh"), timeout=45)
        else:
            sudo("docker cp " + shlex.quote(backup + "/hub_entry.original.py") + " " + shlex.quote(container + ":/app/hub_entry.py"))
        raise
    finally:
        client.close()
