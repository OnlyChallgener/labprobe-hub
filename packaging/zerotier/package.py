"""Build feed-independent OpenWrt IPKs; does not execute installation scripts."""
from __future__ import annotations
import argparse, gzip, hashlib, io, json, tarfile
from pathlib import Path

VERSION = '1.16.2-1'
UPSTREAM = '1.16.2'
PACKAGE = 'zerotier-one-static'
ARCHES = {'BE72': 'aarch64_cortex-a53', 'BE50': 'arm_cortex-a7'}
HERE = Path(__file__).resolve().parent

def archive(items: dict[str, tuple[bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.GNU_FORMAT) as tar:
        for name, (data, mode) in sorted(items.items()):
            assert not name.startswith('/') and '..' not in name.split('/')
            info = tarfile.TarInfo('./' + name)
            info.mode, info.uid, info.gid, info.mtime = mode, 0, 0, 0
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)

def build(binary_dir: Path, public_key: Path, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    pub = public_key.read_bytes()
    result = {}
    for model, arch in ARCHES.items():
        binary = (binary_dir / ('zerotier-one' if model == 'BE72' else 'zerotier-one.arm32')).read_bytes()
        assert binary[:4] == b'\x7fELF'
        assert binary[4] == (2 if model == 'BE72' else 1), 'Wrong ELF class'
        assert int.from_bytes(binary[18:20], 'little') == (183 if model == 'BE72' else 40), 'Wrong ELF machine'
        files = {
            'usr/bin/zerotier-one': (binary, 0o755),
            'etc/zerotier-static/update.pub': (pub, 0o644),
            'etc/zerotier-one/local.conf': (b'{}\n', 0o600),
            'lib/upgrade/keep.d/zerotier-static': (b'/etc/zerotier-one/\n/etc/zerotier-static/\n/etc/config/zerotier_static\n', 0o644),
        }
        for source, target, mode in [
            ('zerotier-static.init', 'etc/init.d/zerotier-static', 0o755),
            ('zerotier_static.config', 'etc/config/zerotier_static', 0o600),
            ('zerotier-cli', 'usr/bin/zerotier-cli', 0o755),
            ('zerotier-idtool', 'usr/bin/zerotier-idtool', 0o755),
            ('zerotier-update', 'usr/sbin/zerotier-update', 0o755),
        ]:
            files[target] = ((HERE / 'files' / source).read_bytes(), mode)
        for license_name in ['LICENSE.txt', 'LICENSE-MPL.txt', 'COPYING']:
            path = binary_dir / license_name
            if path.exists(): files['usr/share/licenses/zerotier-one-static/' + license_name] = (path.read_bytes(), 0o644)
        data_archive = archive(files)
        # OpenWrt's ipkg-build records the uncompressed tar size in bytes, not KiB.
        installed_bytes = len(gzip.decompress(data_archive))
        installed_kb = (installed_bytes + 1023) // 1024
        control = (f'Package: {PACKAGE}\nVersion: {VERSION}\nArchitecture: {arch}\n'
                   f'Installed-Size: {installed_bytes}\nMaintainer: LabProbe local builds\n'
                   'Section: net\nPriority: optional\nLicense: MPL-2.0\n'
                   'Conflicts: zerotier, zerotier-one\nProvides: zerotier-one\n'
                   'Description: ZeroTier One static client for verified Ruijie firmware\n'
                   ' Built without the nonfree controller and SSO; no feed dependencies.\n')
        controls = {'control': (control.encode(), 0o644),
                    'conffiles': (b'/etc/config/zerotier_static\n/etc/zerotier-one/local.conf\n', 0o644)}
        for name in ['preinst', 'postinst', 'prerm']:
            controls[name] = ((HERE / 'files' / name).read_bytes(), 0o755)
        name = f'{PACKAGE}_{VERSION}_{arch}.ipk'
        dest = output / arch
        dest.mkdir(exist_ok=True)
        ipk = archive({'debian-binary': (b'2.0\n', 0o644),
                       'control.tar.gz': (archive(controls), 0o644),
                       'data.tar.gz': (data_archive, 0o644)})
        (dest / name).write_bytes(ipk)
        digest = hashlib.sha256(ipk).hexdigest()
        manifest = (f'format=1\npackage={PACKAGE}\nversion={VERSION}\nupstream={UPSTREAM}\n'
                    f'architecture={arch}\nfile={name}\nsha256={digest}\nbytes={len(ipk)}\n')
        (dest / 'manifest').write_bytes(manifest.encode())
        result[model] = dict(file=f'{arch}/{name}', bytes=len(ipk), installed_kb=installed_kb, installed_bytes=installed_bytes,
                             sha256=digest, binary_sha256=hashlib.sha256(binary).hexdigest())
    for file in ['zerotier-update', 'install.sh']:
        (output / file).write_bytes((HERE / 'files' / file).read_bytes())
    (output / 'update.pub').write_bytes(pub)
    (output / 'build-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.binaries, args.public_key, args.output), indent=2))
