#!/bin/sh
set -eu
cd /work
echo '3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797  go1.26.10.linux-arm64.tar.gz' > go.sha256
if [ ! -f go1.26.10.linux-arm64.tar.gz ]; then
    wget -O go1.26.10.linux-arm64.tar.gz.part https://go.dev/dl/go1.26.10.linux-arm64.tar.gz
    mv go1.26.10.linux-arm64.tar.gz.part go1.26.10.linux-arm64.tar.gz
fi
sha256sum -c go.sha256
echo 'e7c596b37ff27ec487d19b1920f73e0c97a78067ea35766530ee9659ade72711  source.tar.gz' | sha256sum -c -
echo 'a178e00b67acabcda2dcef00afa90be6a7bb261e466a67dad58c8478d9553603  dashboard.tar.gz' | sha256sum -c -
if [ ! -x go/bin/go ]; then tar -xzf go1.26.10.linux-arm64.tar.gz; fi
if [ ! -f mihomo-1.19.33/go.mod ]; then tar -xzf source.tar.gz; fi
export PATH=/work/go/bin:$PATH
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0
export GOPATH=/work/gopath GOCACHE=/work/go-cache GOMAXPROCS=2
export GOPROXY='https://goproxy.cn|https://proxy.golang.org|direct'
mkdir -p /work/out
go version | tee /work/out/toolchain.txt
cd /work/mihomo-1.19.33
go mod download
go build -p 2 -tags with_gvisor -trimpath \
    -ldflags '-X github.com/metacubex/mihomo/constant.Version=v1.19.33 -X github.com/metacubex/mihomo/constant.BuildTime=2026-10-22T00:00:00Z -w -s -buildid=' \
    -o /work/out/mihomo .
/work/out/mihomo -v | tee /work/out/version.txt
go version -m /work/out/mihomo > /work/out/buildinfo.txt
file /work/out/mihomo > /work/out/elf.txt
readelf -l /work/out/mihomo >> /work/out/elf.txt
readelf -d /work/out/mihomo >> /work/out/elf.txt
sha256sum /work/out/mihomo > /work/out/mihomo.sha256
echo BUILD_COMPLETED
