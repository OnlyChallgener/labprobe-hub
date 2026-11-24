"""Isolated fault tests using real usign and modeled opkg/service commands.

Run inside the temporary QA container. No host init, package manager, or identity is used.
"""
from pathlib import Path
import gzip, io, json, os, re, shutil, stat, subprocess, tarfile, tempfile, unittest

WORK = Path('/work')
RELEASE = WORK / 'release'
USIGN = WORK / 'usign-build/usign'
SOURCE = WORK / 'updater-under-test'
ARCH = 'aarch64_cortex-a53'

OPKG = r'''#!/usr/bin/env python3
import os,sys,json,tarfile,io
from pathlib import Path
r=Path(os.environ['TEST_ROOT']);args=sys.argv[1:]
while args and args[0].startswith('--'):args.pop(0)
cmd=args.pop(0)
if cmd=='print-architecture':print('arch all 1\narch '+os.environ.get('MOCK_ARCH','aarch64_cortex-a53')+' 10')
elif cmd=='status':
 p=r/'version'
 if not p.exists():sys.exit(1)
 print('Package: zerotier-one-static\nVersion: '+p.read_text().strip()+'\nStatus: install ok installed')
elif cmd=='compare-versions':
 a,op,b=args
 v=lambda x:tuple(int(t) for t in x.replace('-','.').split('.'))
 sys.exit(0 if (v(a)==v(b) if op=='=' else v(a)>v(b)) else 1)
elif cmd=='install':
 package=Path(args[0]);rollback=package.name=='previous.ipk'
 with (r/'calls').open('a') as f:f.write(('rollback' if rollback else 'install')+'\n')
 if os.environ.get('MOCK_INSTALL_FAIL') and not rollback:sys.exit(1)
 with tarfile.open(package,'r:gz') as t:
  data=t.extractfile('./control.tar.gz').read()
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
  control=t.extractfile('./control').read().decode()
 version=next(x.split(': ',1)[1] for x in control.splitlines() if x.startswith('Version: '))
 (r/'version').write_text(version)
 home=r/'etc/zerotier-one';home.mkdir(parents=True,exist_ok=True)
 if not (home/'identity.secret').exists():(home/'identity.secret').write_text('generated-test-identity')
 if os.environ.get('MOCK_REPLACE_ID') and not rollback:(home/'identity.secret').write_text('wrong-test-identity')
 (r/'usr/bin/zerotier-one').write_text('#!/bin/sh\necho '+version.split('-')[0]+'\n')
 (r/'usr/bin/zerotier-one').chmod(0o755)
 (r/'usr/bin/zerotier-cli').write_text('#!/bin/sh\n[ "${MOCK_BAD_HEALTH:-}" != 1 ]\n')
 (r/'usr/bin/zerotier-cli').chmod(0o755)
else:raise SystemExit('Unexpected opkg command: '+cmd)
'''

def mini_ipk(version):
    def tgz(name, data):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w:gz') as t:
            info=tarfile.TarInfo('./'+name);info.size=len(data);t.addfile(info,io.BytesIO(data))
        return out.getvalue()
    return tgz('control.tar.gz',tgz('control',f'Package: zerotier-one-static\nVersion: {version}\n'.encode()))

class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='zt-updater-')
        self.r=Path(self.tmp.name)
        self.env=dict(os.environ,TEST_ROOT=str(self.r))
        for p in ['etc/zerotier-static/cache','etc/zerotier-one','etc/config','usr/bin','usr/sbin','var/lock','tmp','tools','etc/init.d','dev/net']:
            (self.r/p).mkdir(parents=True,exist_ok=True)
        shutil.copy(RELEASE/'update.pub',self.r/'etc/zerotier-static/update.pub')
        shutil.copytree(RELEASE,self.r/'release')
        self.base=self.r/'release'
        self.env['PATH']=str(self.r/'tools')+':'+os.environ['PATH']
        self.tool('opkg',OPKG)
        self.tool('usign','#!/bin/sh\nexec /work/usign-build/usign "$@"\n')
        self.tool('curl','#!/bin/sh\necho "Network access is forbidden in this test" >&2\nexit 99\n')
        self.tool('uci','#!/bin/sh\necho "${MOCK_ENABLED:-1}"\n')
        self.tool('pidof','#!/bin/sh\n[ "${MOCK_RUNNING:-0}" = 1 ] && echo 12345\n')
        self.tool('sleep','#!/bin/sh\nif [ "$1" = 90 ]; then exec /bin/sleep 90; else exec /bin/sleep 0.01; fi\n')
        self.tool('df','#!/bin/sh\nprintf "Filesystem 1024-blocks Used Available Capacity Mounted\\nmock 99999 1 %s 1%% /\\n" "${MOCK_FREE:-99998}"\n')
        init=self.r/'etc/init.d/zerotier-static';init.write_text('#!/bin/sh\necho "$1" >> "$TEST_ROOT/service-calls"\n');init.chmod(0o755)
        (self.r/'etc/config/zerotier_static').write_text('config service main\n')
        # Rewrite fixed system paths in a copy only. The shipped updater is unchanged.
        text=re.sub(r'/(etc|usr|var|tmp)(?=[/\s"\'])',lambda m:str(self.r)+'/'+m[1],SOURCE.read_text())
        text=text.replace('-C /','-C "'+str(self.r)+'"/')
        self.script=self.r/'update';self.script.write_text(text)

    def tearDown(self): self.tmp.cleanup()

    def tool(self,name,text):
        p=self.r/'tools'/name;p.write_text(text);p.chmod(0o755)

    def run_update(self,*args,ok=True):
        p=subprocess.run(['sh',str(self.script),*map(str,args)],env=self.env,capture_output=True,text=True,timeout=20)
        if ok:self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        else:self.assertNotEqual(p.returncode,0,p.stdout+p.stderr)
        return p

    def old_install(self):
        (self.r/'version').write_text('1.16.1-1')
        (self.r/'etc/zerotier-one/identity.secret').write_text('preserved-test-identity')
        (self.r/'etc/zerotier-static/cache/current.ipk').write_bytes(mini_ipk('1.16.1-1'))

    def calls(self):
        p=self.r/'calls';return p.read_text().splitlines() if p.exists() else []

    def test_valid_check_does_not_install(self):
        self.run_update('--check',self.base)
        self.assertEqual(self.calls(),[])

    def test_valid_arm32_check(self):
        self.env['MOCK_ARCH']='arm_cortex-a7';self.run_update('--check',self.base)

    def test_tampered_manifest_rejected(self):
        p=self.base/ARCH/'manifest';p.write_text(p.read_text().replace('1.16.2','1.16.9'))
        self.run_update('--check',self.base,ok=False);self.assertEqual(self.calls(),[])

    def test_tampered_package_rejected(self):
        p=next((self.base/ARCH).glob('*.ipk'));p.write_bytes(p.read_bytes()+b'bad')
        self.run_update('--check',self.base,ok=False);self.assertEqual(self.calls(),[])

    def test_arch_mismatch_rejected(self):
        for name in ['manifest','manifest.sig']:
            shutil.copy(self.base/'arm_cortex-a7'/name,self.base/ARCH/name)
        self.run_update('--check',self.base,ok=False);self.assertEqual(self.calls(),[])

    def test_initial_install_populates_cache(self):
        self.run_update('--bootstrap',self.base)
        self.assertTrue((self.r/'etc/zerotier-static/cache/current.ipk').is_file())
        self.assertEqual(self.calls(),['install'])

    def test_upgrade_preserves_identity(self):
        self.old_install();self.run_update(self.base)
        self.assertEqual((self.r/'version').read_text(),'1.16.2-1')
        self.assertEqual((self.r/'etc/zerotier-one/identity.secret').read_text(),'preserved-test-identity')

    def test_install_failure_rolls_back(self):
        self.old_install();self.env['MOCK_INSTALL_FAIL']='1'
        self.run_update(self.base,ok=False)
        self.assertEqual(self.calls(),['install','rollback'])
        self.assertEqual((self.r/'version').read_text(),'1.16.1-1')

    def test_failed_health_rolls_back(self):
        self.old_install();self.env['MOCK_BAD_HEALTH']='1'
        self.run_update(self.base,ok=False)
        self.assertEqual(self.calls(),['install','rollback'])
        self.assertEqual((self.r/'version').read_text(),'1.16.1-1')

    def test_disabled_service_can_upgrade(self):
        self.old_install();self.env['MOCK_BAD_HEALTH']='1';self.env['MOCK_ENABLED']='0'
        self.run_update(self.base)
        self.assertEqual(self.calls(),['install'])
        self.assertEqual((self.r/'etc/zerotier-one/identity.secret').read_text(),'preserved-test-identity')

    def test_identity_change_rolls_back(self):
        self.old_install();self.env['MOCK_REPLACE_ID']='1'
        self.run_update(self.base,ok=False)
        self.assertEqual(self.calls(),['install','rollback'])
        self.assertEqual((self.r/'etc/zerotier-one/identity.secret').read_text(),'preserved-test-identity')

    def test_low_flash_refused_before_install(self):
        self.old_install();self.env['MOCK_FREE']='100'
        self.run_update(self.base,ok=False);self.assertEqual(self.calls(),[])

    def test_missing_cache_refused_before_install(self):
        self.old_install();(self.r/'etc/zerotier-static/cache/current.ipk').unlink()
        self.run_update(self.base,ok=False);self.assertEqual(self.calls(),[])

    def test_downgrade_refused(self):
        self.old_install();(self.r/'version').write_text('1.16.3-1')
        self.run_update(self.base,ok=False);self.assertEqual(self.calls(),[])

    def test_bootstrap_cannot_replace_installed_key(self):
        self.old_install();self.run_update('--bootstrap',self.base,ok=False);self.assertEqual(self.calls(),[])

    def test_insecure_http_rejected(self):
        self.run_update('http://example.invalid',ok=False);self.assertEqual(self.calls(),[])

    def preinstall(self,ok=True):
        script=self.r/'preinst'
        text=re.sub(r'/(etc|usr|var|dev)(?=[/\s"\'])',lambda m:str(self.r)+'/'+m[1],(WORK/'preinst-under-test').read_text())
        script.write_text(text)
        p=subprocess.run(['sh',str(script)],env=self.env,capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode==0,ok,p.stdout+p.stderr)

    def test_preinstall_requires_tun(self):
        self.preinstall(ok=False)

    def test_preinstall_clean_router(self):
        os.mknod(self.r/'dev/net/tun',stat.S_IFCHR|0o600,os.makedev(10,200))
        self.preinstall()

    def test_preinstall_blocks_temporary_daemon(self):
        os.mknod(self.r/'dev/net/tun',stat.S_IFCHR|0o600,os.makedev(10,200))
        self.env['MOCK_RUNNING']='1';self.preinstall(ok=False)

    def test_preinstall_blocks_existing_identity(self):
        os.mknod(self.r/'dev/net/tun',stat.S_IFCHR|0o600,os.makedev(10,200))
        (self.r/'etc/zerotier-one/identity.secret').write_text('existing-test-identity')
        self.preinstall(ok=False)

if __name__=='__main__':unittest.main(verbosity=2)
