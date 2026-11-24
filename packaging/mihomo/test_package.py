"""Packaging safety checks; these never install or launch a service."""
import gzip
import importlib.util
import io
import json
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mihomo_ipk_package", HERE / "package.py")
package = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(package)


def elf(machine=183, segment=1):
    data = bytearray(120)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<I", data, 64, segment)
    return bytes(data)


def unpack(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {item.name.removeprefix("./"): (tar.extractfile(item).read(), item.mode) for item in tar if item.isfile()}


class PackageTests(unittest.TestCase):
    def test_arm64_static_required(self):
        package.verify_static_arm64(elf())
        for invalid in (elf(40), elf(segment=2), elf(segment=3), elf()[:70], b"script"):
            with self.subTest(binary=invalid[:20]):
                with self.assertRaises(ValueError):
                    package.verify_static_arm64(invalid)

    def test_archive_deterministic_and_no_parent_paths(self):
        files = {"etc/a": (b"setting\n", 0o600), "usr/bin/app": (b"ELF", 0o755)}
        self.assertEqual(package.archive(files), package.archive(dict(reversed(list(files.items())))))
        self.assertEqual(unpack(package.archive(files)), files)
        for name in ("../secret", "/etc/config", "ui/../../bad"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    package.archive({name: (b"", 0o644)})

    def test_dashboard_rejects_links_and_traversal(self):
        for path, kind in (("../index.html", tarfile.REGTYPE), ("/index.html", tarfile.REGTYPE), ("link", tarfile.SYMTYPE)):
            with self.subTest(path=path):
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                    entry = tarfile.TarInfo(path)
                    entry.type = kind
                    entry.linkname = "/etc/shadow" if kind == tarfile.SYMTYPE else ""
                    tar.addfile(entry, io.BytesIO())
                with self.assertRaises(ValueError):
                    package.dashboard_files(stream.getvalue())

    def test_upstream_input_hash_is_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "archive.tar.gz"
            path.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                package.checked_input(path, {"size": 8, "sha256": "0" * 64})

    def test_compact_profile_version_features_and_measured_guide(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "mihomo-compact"
            binary.write_bytes(elf())
            result = package.build(binary, base / "output", "compact")
            self.assertEqual(result["version"], "1.19.33-2")
            self.assertEqual(result["profile"], "compact")
            self.assertEqual(result["buildTags"], ["no_easytier", "no_zerotier", "no_tailscale"])
            self.assertFalse(result["lowMemoryBuild"])
            self.assertIn("gVisor userspace TCP/IP stack", result["removedFeatures"])
            outer = unpack((base / "output" / result["file"]).read_bytes())
            data = unpack(outer["data.tar.gz"][0])
            embedded = data["usr/share/doc/mihomo-web/README.zh-CN.md"][0].decode()
            guide = (base / "output" / "README.zh-CN.md").read_text(encoding="utf-8")
            self.assertTrue(guide.startswith(embedded))
            self.assertIn("精简版（compact）", guide)
            self.assertIn("120 字节", guide)
            self.assertIn("mihomo-web_1.19.33-2_aarch64_cortex-a53.ipk", guide)
            self.assertNotIn("57,278,590", guide)
            self.assertNotIn("PACKAGE_PROFILE_AND_SIZE", guide)
            self.assertIn(result["sha256"], guide)
            self.assertIn(f"闪存安装归档：{result['installed_bytes']:,} 字节", guide)

    def test_unknown_profile_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with self.assertRaises(ValueError):
                package.build(base / "missing", base / "output", "other")
            self.assertFalse((base / "output").exists())

    def test_native_ipk_structure_conffiles_secrets_and_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "mihomo"
            binary.write_bytes(elf())
            result = package.build(binary, base / "output")
            ipk = (base / "output" / result["file"]).read_bytes()
            outer = unpack(ipk)
            self.assertEqual(set(outer), {"debian-binary", "control.tar.gz", "data.tar.gz"})
            self.assertEqual(outer["debian-binary"][0], b"2.0\n")
            controls = unpack(outer["control.tar.gz"][0])
            data = unpack(outer["data.tar.gz"][0])
            self.assertIn("Architecture: aarch64_cortex-a53\n", controls["control"][0].decode())
            self.assertNotIn("Depends:", controls["control"][0].decode())
            self.assertEqual(controls["conffiles"][0].splitlines(), [b"/etc/config/mihomo_web", b"/etc/mihomo/config.yaml"])
            self.assertNotIn("etc/mihomo/api.secret", data)
            self.assertIn("usr/share/mihomo-web/ui/index.html", data)
            self.assertEqual(gzip.decompress(data["usr/lib/mihomo-web/mihomo.gz"][0]), elf())
            self.assertIn(result["binary_sha256"].encode(), data["usr/bin/mihomo"][0])
            self.assertIn(result["binary_archive_sha256"].encode(), data["usr/bin/mihomo"][0])
            self.assertNotIn(b"@CORE_", data["usr/bin/mihomo"][0])
            self.assertIn(b"CORE_UI='/usr/share/mihomo-web/ui'", data["usr/bin/mihomo"][0])
            self.assertIn(b"export SAFE_PATHS", data["usr/bin/mihomo"][0])
            self.assertNotIn(b"SKIP_SAFE_PATH_CHECK", data["usr/bin/mihomo"][0])
            self.assertEqual(result["ram_core_cache_bytes"], len(elf()))
            self.assertTrue(result["compressed_core"])
            self.assertIn("usr/share/licenses/mihomo-web/mihomo-LICENSE", data)
            self.assertIn("usr/share/licenses/mihomo-web/metacubexd-LICENSE", data)
            self.assertEqual(data["etc/mihomo/config.yaml"][1], 0o600)
            self.assertEqual(data["etc/init.d/mihomo-web"][1], 0o755)
            self.assertEqual(result["installed_bytes"], len(gzip.decompress(outer["data.tar.gz"][0])))
            self.assertEqual(result["payload_bytes"], sum(len(entry[0]) for entry in data.values()))
            self.assertEqual(json.loads((base / "output" / "build-result.json").read_text()), result)
            # First-install lifecycle must not activate networking services.
            postinst_commands = [line.strip() for line in controls["postinst"][0].decode().splitlines()]
            self.assertFalse(any(line.startswith("/etc/init.d/mihomo-web") for line in postinst_commands))


if __name__ == "__main__":
    unittest.main()
