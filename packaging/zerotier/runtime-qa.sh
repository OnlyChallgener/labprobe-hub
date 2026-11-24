#!/bin/sh
set -eu
cd /work
file zerotier-one zerotier-one.arm32
for file in zerotier-one zerotier-one.arm32; do
    readelf -l "$file" | grep INTERP && exit 1
    readelf -d "$file" | grep NEEDED && exit 1
    readelf -h -A "$file" > "$file.elf.txt"
done
qemu-arm -cpu cortex-a7,vfp=off,neon=off,vfp-d32=off ./zerotier-one.arm32 -v
qemu-arm -cpu cortex-a7,vfp=off,neon=off,vfp-d32=off ./arm32/ZeroTierOne-1.16.2/zerotier-selftest > /work/selftest-arm32.log 2>&1
echo ARM32_SELFTEST_OK
mkdir -m 700 /tmp/zt-qa-native /tmp/zt-qa-arm32
./zerotier-one -p29993 /tmp/zt-qa-native > /tmp/zt-native.log 2>&1 &
native=$!
qemu-arm -cpu cortex-a7,vfp=off,neon=off,vfp-d32=off ./zerotier-one.arm32 -p29994 /tmp/zt-qa-arm32 > /tmp/zt-arm32.log 2>&1 &
arm32=$!
trap 'kill "$native" "$arm32" 2>/dev/null || true' EXIT
for arch in native arm32; do
    good=0
    for attempt in $(seq 1 30); do
        if [ "$arch" = native ]; then
            ./zerotier-one -q -D/tmp/zt-qa-native info > /tmp/zt-native-info 2>/dev/null && good=1
        else
            qemu-arm -cpu cortex-a7,vfp=off,neon=off,vfp-d32=off ./zerotier-one.arm32 -q -D/tmp/zt-qa-arm32 info > /tmp/zt-arm32-info 2>/dev/null && good=1
        fi
        [ "$good" = 0 ] || break
        sleep 1
    done
    [ "$good" = 1 ] || { cat /tmp/zt-$arch.log; exit 1; }
    echo "$arch local API OK"
done
echo RUNTIME_QA_OK
