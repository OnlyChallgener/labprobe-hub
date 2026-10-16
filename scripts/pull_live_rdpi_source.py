"""Read-only snapshot of the deployed RDPI sources for a surgical update."""
import hashlib
import sys
from pathlib import Path

import paramiko

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ShinyaHub" / "scripts"))
from deploy_to_nas import NAS_PASS, NAS_USER


root = Path(__file__).resolve().parents[1]
target = root / "test_tmp_childguard_20261015" / "live_rdpi"
target.mkdir(parents=True, exist_ok=True)
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("36.157.252.49", port=6011, username=NAS_USER, password=NAS_PASS, timeout=10)
try:
    for name in ("hub.py", "rdpi_signature_service.py"):
        stdin, stdout, stderr = client.exec_command("sudo -S docker exec labprobe-hub cat /app/" + name, timeout=25)
        stdin.write(NAS_PASS + "\n")
        stdin.flush()
        data = stdout.read()
        error = stderr.read().decode("utf-8", "replace")
        if stdout.channel.recv_exit_status():
            raise RuntimeError(name + ": " + error[-180:])
        (target / name).write_bytes(data)
        print(name, len(data), hashlib.sha256(data).hexdigest())
finally:
    client.close()
