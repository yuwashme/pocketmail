"""Build a local DSM prototype from one explicitly supplied static Linux ELF."""
import argparse
import gzip
import hashlib
import io
import struct
import tarfile
import tomllib
import zlib
from pathlib import Path

BASE = Path(__file__).resolve().parent
ID = 'pocketmail'
MACHINES = {'rtd1296': 183, 'geminilake': 62}


def check_binary(data, arch):
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('expected little-endian 64-bit ELF')
    hdr = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    if hdr[0] not in (2, 3) or hdr[1] != MACHINES[arch] or not hdr[3]:
        raise ValueError('wrong executable type, entry point or CPU for ' + arch)
    off, size, count = hdr[4], hdr[8], hdr[9]
    if size != 56 or not count or off + size * count > len(data):
        raise ValueError('invalid program headers')
    kinds = [struct.unpack_from('<I', data, off + i*size)[0] for i in range(count)]
    if 1 not in kinds or 3 in kinds:
        raise ValueError('expected loadable binary without external ELF interpreter')
    if any(pattern in data for pattern in (b'/Users/', b'/home/', b'-----BEGIN PRIVATE KEY-----')):
        raise ValueError('binary contains a personal build path or key marker; rebuild in isolation')


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
    return output.getvalue()


def icon(n):
    # Original envelope mark, drawn on an integer grid.
    def pixel(x, y):
        x, y = x*64//n, y*64//n
        if 7 <= x < 57 and 15 <= y < 49:
            return b'\x18\x39\x52' if abs(y-16-min(x-7, 56-x)*0.7) < 2 else b'\xef\xf7\xf5'
        return b'\x15\x6b\x70'
    def chunk(t, data):
        return struct.pack('>I', len(data)) + t + data + struct.pack('>I', zlib.crc32(t+data))
    pixels = b''.join(b'\0' + b''.join(pixel(x, y) for x in range(n)) for y in range(n))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', n,n,8,2,0,0,0))
            + chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))


def build(binary, arch, dest):
    data = binary.read_bytes()
    check_binary(data, arch)
    src = BASE/'dsm'
    lic = (BASE.parent/'LICENSE').read_bytes()
    payload = gzip.compress(archive({'bin/synology-mail-server': (data, 0o755),
                                     'bin/serve': ((src/'serve').read_bytes(), 0o755)}), mtime=0)
    version = tomllib.loads((BASE.parent/'Cargo.toml').read_text())['package']['version'] + '-1'
    fields = dict(package=ID, displayname='Pocketmail (preview)', version=version,
                  os_min_ver='7.2.2-72806', arch=arch, maintainer='Pocketmail contributors',
                  description='Private IMAP mail store. Local evaluation build.', install_type='volume',
                  checksum=hashlib.md5(payload).hexdigest())
    files = {'INFO': (''.join(f'{k}="{v}"\n' for k,v in fields.items()).encode(), 0o644),
             'package.tgz': (payload, 0o644), 'LICENSE': (lic, 0o644),
             'conf/privilege': (b'{"defaults":{"run-as":"package"}}\n', 0o644),
             'conf/resource': (b'{"systemd-user-unit":{}}\n', 0o644),
             'conf/systemd/pkguser-pocketmail.service': ((src/'service').read_bytes(), 0o644),
             'PACKAGE_ICON.PNG': (icon(64), 0o644), 'PACKAGE_ICON_256.PNG': (icon(256), 0o644)}
    for hook in ('preinst','postinst','preupgrade','postupgrade','preuninst','postuninst','start-stop-status'):
        script = (src/'prepare').read_bytes() if hook in ('postinst','postupgrade') else b'#!/bin/sh\nexit 0\n'
        files['scripts/'+hook] = ((src/hook).read_bytes() if hook == 'start-stop-status' else script, 0o755)
    dest.mkdir(parents=True, exist_ok=True)
    path = dest/f'{ID}-{arch}-{version}.spk'
    path.write_bytes(archive(files))
    return path


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary', type=Path)
    p.add_argument('--arch', choices=MACHINES, required=True)
    p.add_argument('--out', type=Path, default=BASE/'dist')
    args = p.parse_args()
    print(build(args.binary, args.arch, args.out))
