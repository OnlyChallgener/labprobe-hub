#!/bin/sh
set -eu
cd /work
apk add --no-cache cmake qemu-arm
wget -q -O usign.tar.xz https://sources.openwrt.org/usign-2020-05-23-f1f65026.tar.xz
echo '3f6569a5e63fdfd032976ac0f79d736d3935101ac1b97fb370514b013c5e6bb6  usign.tar.xz' | sha256sum -c -
tar -xf usign.tar.xz
cmake -S usign-2020-05-23-f1f65026 -B usign-build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build usign-build -j2
cp /usr/bin/qemu-arm /work/qemu-arm
cp -L /lib/ld-musl-aarch64.so.1 /work/qa-libc.so
echo QA_TOOLS_READY
