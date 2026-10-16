import sys,tarfile,io,json,shlex,datetime
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"ShinyaHub"/"scripts"))
from deploy_to_nas import NAS_PASS,NAS_USER
from eweb_hub_remote import connect,run
root=Path(__file__).resolve().parents[1]
stage="/tmp/labprobe-master-0276"
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode="w:gz") as tar:
    for name in ("Cargo.toml","Cargo.lock","build.rs","src"):
        tar.add(root/"labrelay"/name,arcname=name)
c=connect("36.157.252.49",6011,NAS_USER,NAS_PASS)
try:
    sudo=lambda cmd,**kw:run(c,cmd,sudo_password=NAS_PASS,**kw)
    sudo("mkdir -p "+stage)
    sudo("tee "+stage+"/source.tar.gz",stdin=buf.getvalue())
    sudo("tar -xzf "+stage+"/source.tar.gz -C "+stage)
    script="""#!/bin/sh
set -eu
apt-get update -qq
apt-get install -y -qq --no-install-recommends musl-tools >/dev/null
rustup target add aarch64-unknown-linux-musl
cargo test --locked child_guard::tests
CC_aarch64_unknown_linux_musl=musl-gcc CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc cargo build --locked --release --target aarch64-unknown-linux-musl
./target/aarch64-unknown-linux-musl/release/labrelay version
"""
    sudo("tee "+stage+"/build.sh",stdin=script.encode())
    cmd="docker run -d --name labrelay-master-0276 --pull never -v "+stage+":/src -w /src -e CARGO_BUILD_JOBS=2 rust:1-bookworm sh /src/build.sh"
    print(sudo(cmd).decode().strip())
finally:c.close()
