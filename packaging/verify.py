"""Inspect the actual SPK, then exercise its hooks with a disposable DSM-like tree."""
import hashlib
import io
import json
import os
import shlex
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from build import check_binary

with tarfile.open(sys.argv[1]) as spk:
    hooks = 'preinst postinst preupgrade postupgrade preuninst postuninst start-stop-status'.split()
    assert set(spk.getnames()) == {
        'INFO','PACKAGE_ICON.PNG','PACKAGE_ICON_256.PNG','LICENSE','package.tgz','conf/resource',
        'conf/privilege','conf/systemd/pkguser-pocketmail.service', *('scripts/'+h for h in hooks)}
    read = lambda name: spk.extractfile(name).read()
    info = dict(line.split('=', 1) for line in shlex.split(read('INFO').decode()))
    assert info['package'] == 'pocketmail'
    payload = read('package.tgz')
    assert hashlib.md5(payload).hexdigest() == info['checksum']
    assert json.loads(read('conf/privilege')) == {'defaults': {'run-as': 'package'}}
    for n, key in [(64,'PACKAGE_ICON.PNG'),(256,'PACKAGE_ICON_256.PNG')]:
        assert struct.unpack('>II', read(key)[16:24]) == (n,n)
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as inner:
        assert set(inner.getnames()) == {'bin/serve', 'bin/synology-mail-server'}
        check_binary(inner.extractfile('bin/synology-mail-server').read(), info['arch'])
        wrapper = inner.extractfile('bin/serve').read().decode()
    with tempfile.TemporaryDirectory() as folder:
        base = Path(folder)/'pocketmail'
        for d in ['var','etc','target/bin']:
            (base/d).mkdir(parents=True)
        env = dict(PATH=os.defpath, SYNOPKG_PKGVAR=str(base/'var'), SYNOPKG_PKGNAME=base.name)
        def hook(h):
            assert spk.getmember('scripts/'+h).mode == 0o755
            script = read('scripts/'+h).decode().replace('/var/packages/', folder+'/')
            subprocess.run(['/bin/sh','-eu','-c', script], env=env, check=True)
        for h in hooks:
            subprocess.run(['/bin/sh','-n'], input=read('scripts/'+h), check=True)
        hook('preinst')
        hook('postinst')
        for d in ['etc/private','var/store']:
            assert (base/d).stat().st_mode & 0o777 == 0o700
            (base/d/'sentinel').write_text(d)
        # Old uninstall hooks also execute during DSM upgrade.
        for h in ['preupgrade','preuninst','postuninst','preinst','postinst','postupgrade','preuninst','postuninst']:
            hook(h)
        for d in ['etc/private','var/store']:
            assert (base/d/'sentinel').read_text() == d
        # Substitute only the DSM root and a dummy executable that reports its environment.
        stub = base/'target/bin/synology-mail-server'
        stub.write_text('#!/bin/sh\n[ "$1" = serve ] || exit 2\nenv\n')
        stub.chmod(0o755)
        def run():
            return subprocess.run(['/bin/sh','-c',wrapper.replace('/var/packages/pocketmail',shlex.quote(str(base)))],
                                  env=dict(env, SSM_PULL_URL='https://invalid.example'),capture_output=True)
        r = run()
        assert r.returncode == 0 and b'SSM_PULL_URL=' not in r.stdout and b'SSM_WEB_LISTEN=off' in r.stdout
        (base/'etc/private/key.pem').touch()
        assert run().returncode != 0
        (base/'etc/private/cert.pem').touch()
        assert b'SSM_TLS_CERT=' in run().stdout
print('PASS: archive, binary CPU, checksums, icons, scripts, retention, private modes and startup defaults')
