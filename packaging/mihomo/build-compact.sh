#!/bin/sh
set -eu
cd /work
if [ ! -f go1.26.10.linux-arm64.tar.gz ]; then
    wget -O go1.26.10.linux-arm64.tar.gz.part https://go.dev/dl/go1.26.10.linux-arm64.tar.gz
    mv go1.26.10.linux-arm64.tar.gz.part go1.26.10.linux-arm64.tar.gz
fi
echo '3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797  go1.26.10.linux-arm64.tar.gz' | sha256sum -c -
echo 'e7c596b37ff27ec487d19b1920f73e0c97a78067ea35766530ee9659ade72711  source.tar.gz' | sha256sum -c -
echo 'a178e00b67acabcda2dcef00afa90be6a7bb261e466a67dad58c8478d9553603  dashboard.tar.gz' | sha256sum -c -
[ -x go/bin/go ] || tar -xzf go1.26.10.linux-arm64.tar.gz
[ -f mihomo-1.19.33/go.mod ] || tar -xzf source.tar.gz
export PATH=/work/go/bin:$PATH
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0
export GOPATH=/work/gopath GOCACHE=${MIHOMO_GOCACHE:-/work/go-cache} GOMAXPROCS=2
export GOPROXY='https://goproxy.cn|https://proxy.golang.org|direct'
cd /work/mihomo-1.19.33
mkdir -p /work/out-compact
go build -p 2 -tags no_easytier,no_zerotier,no_tailscale -trimpath -ldflags '-X github.com/metacubex/mihomo/constant.Version=v1.19.33 -X github.com/metacubex/mihomo/constant.BuildTime=2026-10-22T00:00:00Z -w -s -buildid=' -o /work/out-compact/mihomo .
/work/out-compact/mihomo -v | tee /work/out-compact/version.txt
go version -m /work/out-compact/mihomo > /work/out-compact/buildinfo.txt
file /work/out-compact/mihomo > /work/out-compact/elf.txt
readelf -l /work/out-compact/mihomo >> /work/out-compact/elf.txt
readelf -d /work/out-compact/mihomo >> /work/out-compact/elf.txt
sha256sum /work/out-compact/mihomo > /work/out-compact/mihomo.sha256
ls -l /work/out-compact/mihomo
echo BUILD_COMPLETED
