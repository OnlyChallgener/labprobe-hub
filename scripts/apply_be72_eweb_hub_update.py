"""Apply a verified follow-up to an already-installed BE72 eWeb HUB extension.

The caller supplies an authenticated SSH client. No service restart is needed.
"""
from __future__ import annotations
import datetime
import hashlib
import json
import shlex
from pathlib import Path
from scripts.eweb_hub_remote import run, read, write

STATIC = "/www/luci-static/eweb-ehr-exp/static/"
CACHE = "/tmp/luci-modulecache/6C7563692E6D6F64756C65732E6C616270726F6265"

def apply_update(router, folder: Path) -> dict:
    proof = json.loads((folder / "deployment.json").read_text(encoding="utf-8"))
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    agent = json.loads(read(router, "/etc/labprobe/agent.json"))
    if agent.get("routerName") != "BE72" or agent.get("hubUrl") != "http://192.168.5.46:58443":
        raise RuntimeError("Router/Hub binding changed")
    targets = {"labprobe.lua": "/usr/lib/lua/luci/modules/labprobe.lua",
               "hub-pages.js": STATIC + "labprobe/hub-pages.js",
               "hub-pages.js.gz": STATIC + "labprobe/hub-pages.js.gz",
               "hub-pages.css": STATIC + "labprobe/hub-pages.css",
               "hub-pages.css.gz": STATIC + "labprobe/hub-pages.css.gz",
               "app6894ab6e311358c0df7b.js.gz": STATIC + "js/app6894ab6e311358c0df7b.js.gz"}
    # Native firmware normally only stores the gzip main bundle. Preserve that
    # serving arrangement, while also updating a plain copy if one exists.
    plain_name = "app6894ab6e311358c0df7b.js"
    plain_path = STATIC + "js/" + plain_name
    if run(router, "test ! -f " + shlex.quote(plain_path) + " || echo present").strip():
        targets[plain_name] = plain_path
    if 'labprobe-wg-status' in manifest['files']:
        targets['labprobe-wg-status'] = '/usr/libexec/labprobe-wg-status'
    digest = lambda data: hashlib.sha256(data).hexdigest()
    original = {name: read(router, path) if run(router, 'test ! -f ' + shlex.quote(path) + ' || echo present').strip() else None for name, path in targets.items()}
    for name in targets:
        expected = proof["candidateHashes"].get(name)
        if (original[name] is not None and (expected is None or digest(original[name]) != expected)) or (original[name] is None and expected is not None):
            raise RuntimeError("Live asset changed: " + name)
        if digest((folder / name).read_bytes()) != manifest["files"][name]:
            raise RuntimeError("Candidate changed: " + name)
    backup = "/etc/labprobe/backups/eweb-hub-fix-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run(router, "mkdir -p " + shlex.quote(backup) + " && chmod 700 " + shlex.quote(backup))
    rollback = ["#!/bin/sh", "set -eu"]
    for name, path in targets.items():
        if original[name] is not None:
            write(router, backup + "/" + name + ".original", original[name])
        write(router, backup + "/" + name + ".candidate", (folder / name).read_bytes())
        rollback.append(("cp -p " + shlex.quote(backup + "/" + name + ".original") + " " + shlex.quote(path)) if original[name] is not None else 'rm -f ' + shlex.quote(path))
    rollback.append("rm -f " + shlex.quote(CACHE))
    write(router, backup + "/rollback.sh", ("\n".join(rollback) + "\n").encode(), "700")
    run(router, "lua -e " + shlex.quote('assert(loadfile("' + backup + '/labprobe.lua.candidate"))'))
    try:
        for name, path in targets.items():
            write(router, path, (folder / name).read_bytes(), '755' if name == 'labprobe-wg-status' else '644')
            if digest(read(router, path)) != manifest["files"][name]:
                raise RuntimeError("Uploaded asset changed: " + name)
        run(router, "rm -f " + shlex.quote(CACHE))
    except Exception:
        run(router, "sh " + shlex.quote(backup + "/rollback.sh"))
        raise
    proof["version"] = manifest["version"]
    proof["candidateHashes"] = manifest["files"]
    proof.setdefault("followupBackups", []).append(backup)
    (folder / "deployment.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    return {"deployed": True, "version": proof["version"], "changedFiles": list(targets),
            "backup": backup, "serviceRestarts": 0}
