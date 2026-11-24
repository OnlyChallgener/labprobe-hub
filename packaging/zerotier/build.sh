#!/bin/sh
set -eu
cd /work
if [ ! -f ZeroTierOne-1.16.2/version.h ]; then
    wget -O source-1.16.2.tar.gz https://codeload.github.com/zerotier/ZeroTierOne/tar.gz/refs/tags/1.16.2
    echo '2c607f573c6e38815433af289d364a689a203b18b51125f06c4472014d0657f0  source-1.16.2.tar.gz' | sha256sum -c -
    sha256sum source-1.16.2.tar.gz > source.sha256
    tar -xzf source-1.16.2.tar.gz
fi
cd ZeroTierOne-1.16.2
make -j2 ZT_STATIC=1 ZT_SSO_SUPPORTED=0 ZT_NONFREE=0 ZT_CONTROLLER=0 \
    CC=gcc CXX=g++ CFLAGS='-O2 -fstack-protector' CXXFLAGS='-O2 -fstack-protector' \
    LDFLAGS='-static' zerotier-one selftest
./zerotier-one -v
./zerotier-selftest > /work/selftest.log 2>&1
cp zerotier-one /work/zerotier-one.unstripped
strip -o /work/zerotier-one zerotier-one
file /work/zerotier-one
readelf -l /work/zerotier-one
readelf -d /work/zerotier-one
sha256sum /work/zerotier-one
