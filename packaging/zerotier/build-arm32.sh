#!/bin/sh
set -eu
cd /work
if [ ! -x zig-aarch64-linux-0.14.1/zig ]; then
    wget -O zig.tar.xz https://ziglang.org/download/0.14.1/zig-aarch64-linux-0.14.1.tar.xz
    echo 'f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b  zig.tar.xz' | sha256sum -c -
    tar -xf zig.tar.xz
fi
mkdir -p arm32
if [ ! -f arm32/ZeroTierOne-1.16.2/version.h ]; then
    echo '2c607f573c6e38815433af289d364a689a203b18b51125f06c4472014d0657f0  source-1.16.2.tar.gz' | sha256sum -c -
    tar -xzf source-1.16.2.tar.gz -C arm32
fi
cat > /work/cc-arm32 <<'EOF'
#!/bin/sh
exec /work/zig-aarch64-linux-0.14.1/zig cc -target arm-linux-musleabi -mcpu=cortex_a7 -mfloat-abi=soft "$@"
EOF
cat > /work/cxx-arm32 <<'EOF'
#!/bin/sh
exec /work/zig-aarch64-linux-0.14.1/zig c++ -target arm-linux-musleabi -mcpu=cortex_a7 -mfloat-abi=soft "$@"
EOF
chmod 755 /work/cc-arm32 /work/cxx-arm32
cd arm32/ZeroTierOne-1.16.2
make -j2 ZT_STATIC=1 ZT_SSO_SUPPORTED=0 ZT_NONFREE=0 ZT_CONTROLLER=0 ZT_EXTOSDEP= \
    DEFS='' CC_MACH=arm CC=/work/cc-arm32 CXX=/work/cxx-arm32 \
    CFLAGS='-O2 -fstack-protector' CXXFLAGS='-O2 -fstack-protector' \
    LDFLAGS='-static' zerotier-one selftest
cp zerotier-one /work/zerotier-one.arm32.unstripped
/work/zig-aarch64-linux-0.14.1/zig objcopy --strip-all zerotier-one /work/zerotier-one.arm32
file /work/zerotier-one.arm32
readelf -h -A /work/zerotier-one.arm32
sha256sum /work/zerotier-one.arm32
