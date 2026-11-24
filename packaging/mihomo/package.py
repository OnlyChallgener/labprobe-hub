"""Build a feed-independent, native BE72 opkg package without installing it."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import struct
import tarfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
PACKAGE = "mihomo-web"
ARCH = "aarch64_cortex-a53"
MAX_INSTALLED_BYTES = 45 * 1024 * 1024
COMMON_PROTOCOLS = ["Shadowsocks", "Trojan", "VMess", "VLESS", "Hysteria2", "TUIC"]
PROFILES = {
    "standard": {"release": "1", "title": "标准版", "buildTags": ["with_gvisor"], "removedFeatures": []},
    "compact": {
        "release": "2", "title": "精简版",
        "buildTags": ["no_easytier", "no_zerotier", "no_tailscale"],
        "removedFeatures": ["EasyTier outbound", "ZeroTier outbound", "Tailscale outbound", "gVisor userspace TCP/IP stack"],
    },
}


def archive(items: dict[str, tuple[bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, (data, mode) in sorted(items.items()):
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError(f"Unsafe archive path: {name}")
            info = tarfile.TarInfo("./" + str(path))
            info.mode, info.uid, info.gid, info.mtime = mode, 0, 0, 0
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)


def verify_static_arm64(binary: bytes) -> None:
    if len(binary) < 64 or binary[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a little-endian ELF64 executable")
    if struct.unpack_from("<H", binary, 18)[0] != 183:
        raise ValueError("Expected AArch64 (BE72) machine type")
    offset = struct.unpack_from("<Q", binary, 32)[0]
    size, count = struct.unpack_from("<HH", binary, 54)
    if size < 56 or offset + size * count > len(binary):
        raise ValueError("Invalid ELF program header table")
    for index in range(count):
        kind = struct.unpack_from("<I", binary, offset + index * size)[0]
        if kind in (2, 3):  # PT_DYNAMIC / PT_INTERP
            raise ValueError("Binary needs a dynamic loader or shared libraries")


def checked_input(path: Path, expected: dict) -> bytes:
    data = path.read_bytes()
    if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
        raise ValueError(f"Upstream archive does not match versions.json: {path.name}")
    return data


def dashboard_files(data: bytes) -> dict[str, tuple[bytes, int]]:
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for item in tar:
            path = PurePosixPath(item.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"Unsafe dashboard path: {item.name}")
            if item.isdir():
                continue
            if not item.isfile():
                raise ValueError(f"Unsupported dashboard member: {item.name}")
            content = tar.extractfile(item)
            assert content is not None
            result["usr/share/mihomo-web/ui/" + str(path)] = (content.read(), 0o644)
    if "usr/share/mihomo-web/ui/index.html" not in result:
        raise ValueError("Dashboard release lacks index.html")
    return result


def render_readme(version: str, profile: str, core_bytes: int, compressed_bytes: int, ui_bytes: int) -> str:
    selected = PROFILES[profile]
    notice = (
        f"本次构建：**{selected['title']}（{profile}），版本 {version}**。\n\n"
        f"原始内核：**{core_bytes:,} 字节，{core_bytes / 1024 / 1024:.2f} MiB**；"
        f"闪存上的 gzip 内核：**{compressed_bytes:,} 字节，{compressed_bytes / 1024 / 1024:.2f} MiB**；"
        f"完整离线页面：**{ui_bytes:,} 字节，{ui_bytes / 1024 / 1024:.2f} MiB**。"
        "`/tmp` 内核文件缓存占用等于上面的原始内核大小，进程堆和连接另需内存。\n\n"
        "构建标签：`" + ",".join(selected["buildTags"]) + "`。\n\n"
    )
    if profile == "compact":
        notice += (
            "精简版移除了 Mihomo 内置的 EasyTier、ZeroTier、Tailscale 出站，以及 gVisor 用户态协议栈；"
            "保留 Shadowsocks、Trojan、VMess、VLESS、Hysteria2、TUIC 等常用代理协议和完整 MetaCubeXD 页面。"
            "这不会卸载或修改路由器独立安装的 ZeroTier/Tailscale 等软件。"
            "未使用 `with_low_memory` 构建标签，未通过降低工作缓冲区来缩减体积。\n"
            "\n后续持久升级请安装新版精简版 IPK，并按本文检查配置、重启服务。"
            "面板自带的内核升级操作不属于此包的持久升级方式：它可能只修改内存中的临时内核，"
            "下次经过启动入口时会按固定校验值恢复包内版本。升级 IPK 会保留配置、订阅缓存和 API 密钥。\n"
        )
    else:
        notice += "标准版包含 gVisor 及上游默认功能；未使用 `with_low_memory` 构建标签。\n"
    text = (HERE / "README.zh-CN.md").read_text(encoding="utf-8")
    text = text.replace("<!-- PACKAGE_PROFILE_AND_SIZE -->", notice)
    text = text.replace("mihomo-web_1.19.33-1_aarch64_cortex-a53.ipk", f"mihomo-web_{version}_{ARCH}.ipk")
    return text


def build(binary: Path, output: Path, profile: str = "standard") -> dict:
    if profile not in PROFILES:
        raise ValueError(f"Unknown build profile: {profile}")
    selected = PROFILES[profile]
    versions = json.loads((HERE / "versions.json").read_text(encoding="utf-8-sig"))
    version = versions["mihomoVersion"] + "-" + selected["release"]
    core = binary.read_bytes()
    verify_static_arm64(core)
    dashboard = checked_input(HERE / "dashboard.tar.gz", versions["dashboard"])
    source = checked_input(HERE / "source.tar.gz", versions["source"])
    files = dashboard_files(dashboard)
    core_archive = gzip.compress(core, compresslevel=9, mtime=0)
    core_sha256 = hashlib.sha256(core).hexdigest()
    core_archive_sha256 = hashlib.sha256(core_archive).hexdigest()
    wrapper = (HERE / "files" / "mihomo-wrapper").read_text(encoding="utf-8")
    wrapper = (wrapper.replace("@CORE_SHA256@", core_sha256)
               .replace("@CORE_GZIP_SHA256@", core_archive_sha256)
               .replace("@CORE_BYTES@", str(len(core))))
    files["usr/bin/mihomo"] = (wrapper.encode(), 0o755)
    files["usr/lib/mihomo-web/mihomo.gz"] = (core_archive, 0o644)
    for source_name, target, mode in [
        ("mihomo-web.init", "etc/init.d/mihomo-web", 0o755),
        ("mihomo_web.config", "etc/config/mihomo_web", 0o600),
        ("config.yaml", "etc/mihomo/config.yaml", 0o600),
        ("functions.sh", "usr/libexec/mihomo-web/functions.sh", 0o644),
        ("mihomo-web", "usr/sbin/mihomo-web", 0o755),
        ("keep", "lib/upgrade/keep.d/mihomo-web", 0o644),
    ]:
        content = (HERE / "files" / source_name).read_bytes()
        if b"\r" in content:
            raise ValueError(f"Shell/config file needs Unix line endings: {source_name}")
        files[target] = (content, mode)
    with tarfile.open(fileobj=io.BytesIO(source), mode="r:gz") as tar:
        license_file = tar.extractfile(f"mihomo-{versions['mihomoVersion']}/LICENSE")
        assert license_file is not None
        files["usr/share/licenses/mihomo-web/mihomo-LICENSE"] = (license_file.read(), 0o644)
    files["usr/share/licenses/mihomo-web/metacubexd-LICENSE"] = (
        (HERE / "dashboard-LICENSE").read_bytes(), 0o644
    )
    ui_bytes = sum(len(v[0]) for k, v in files.items() if "/ui/" in k)
    readme = render_readme(version, profile, len(core), len(core_archive), ui_bytes)
    files["usr/share/doc/mihomo-web/README.zh-CN.md"] = (readme.encode(), 0o644)
    files["usr/share/doc/mihomo-web/versions.json"] = (
        (json.dumps(versions, ensure_ascii=False, indent=2) + "\n").encode(), 0o644
    )
    data_archive = archive(files)
    payload_bytes = sum(len(content) for content, _ in files.values())
    installed_bytes = len(gzip.decompress(data_archive))
    if installed_bytes > MAX_INSTALLED_BYTES:
        raise ValueError(f"Installed archive needs {installed_bytes} bytes; BE72 packaging limit is 45 MiB")
    control = (
        f"Package: {PACKAGE}\nVersion: {version}\nArchitecture: {ARCH}\n"
        f"Installed-Size: {installed_bytes}\nMaintainer: LabProbe local builds\n"
        "Section: net\nPriority: optional\nLicense: GPL-3.0-only AND MIT\n"
        "Conflicts: mihomo, clash-meta\nProvides: mihomo\n"
        "Description: Static Mihomo with bundled MetaCubeXD dashboard for BE72\n"
        " LAN controller, native procd service; no feed dependencies or automatic routing changes.\n"
    )
    controls = {
        "control": (control.encode(), 0o644),
        "conffiles": (b"/etc/config/mihomo_web\n/etc/mihomo/config.yaml\n", 0o644),
    }
    for name in ("preinst", "postinst", "prerm"):
        controls[name] = ((HERE / "files" / name).read_bytes(), 0o755)
    package_data = archive({
        "debian-binary": (b"2.0\n", 0o644),
        "control.tar.gz": (archive(controls), 0o644),
        "data.tar.gz": (data_archive, 0o644),
    })
    output.mkdir(parents=True, exist_ok=True)
    filename = f"{PACKAGE}_{version}_{ARCH}.ipk"
    package_path = output / filename
    package_path.write_bytes(package_data)
    result = {
        "package": PACKAGE, "version": version, "architecture": ARCH,
        "profile": profile, "buildTags": selected["buildTags"], "removedFeatures": selected["removedFeatures"],
        "retainedCommonProtocols": COMMON_PROTOCOLS, "lowMemoryBuild": False,
        "file": filename, "bytes": len(package_data),
        "installed_bytes": installed_bytes, "payload_bytes": payload_bytes,
        "installed_mib": round(installed_bytes / 1024 / 1024, 2),
        "sha256": hashlib.sha256(package_data).hexdigest(),
        "binary_bytes": len(core), "binary_sha256": core_sha256,
        "compressed_core": True, "binary_archive_bytes": len(core_archive),
        "binary_archive_sha256": core_archive_sha256,
        "ram_core_cache_bytes": len(core),
        "runtime_cache_default": f"/tmp/mihomo-web-core/{core_sha256}/mihomo",
        "dashboard_version": versions["dashboardVersion"],
        "dashboard_payload_bytes": ui_bytes,
        "upstream": versions,
        "validation": {"static_elf64_aarch64": True, "on_router_installed": False},
    }
    (output / "build-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (output / "SHA256SUMS").write_text(result["sha256"] + "  " + filename + "\n", encoding="ascii")
    final_receipt = (
        "\n## 本次交付文件\n\n"
        f"- 安装包：`{filename}`\n"
        f"- IPK 大小：{len(package_data):,} 字节，{len(package_data) / 1024 / 1024:.2f} MiB\n"
        f"- 闪存安装归档：{installed_bytes:,} 字节，{installed_bytes / 1024 / 1024:.2f} MiB\n"
        f"- SHA-256：`{result['sha256']}`\n"
    )
    (output / "README.zh-CN.md").write_text(readme + final_receipt, encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=PROFILES, default="standard")
    args = parser.parse_args()
    print(json.dumps(build(args.binary, args.output, args.profile), indent=2))
