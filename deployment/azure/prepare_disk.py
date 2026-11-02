#!/usr/bin/python3
"""Explicit LUN0 only. Never format a signature, partition, mounted or nonblank disk."""
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/opt/honeypot-data')


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def action(info, signatures, allow_format, blank_edges):
    if info['type'] != 'disk' or info.get('children') or info.get('mountpoints', [None]) not in ([None], []):
        raise ValueError('LUN0 must be an unpartitioned, unmounted managed disk')
    filesystem = info.get('fstype')
    if filesystem == 'ext4':
        return 'mount_existing'
    if filesystem or signatures or not allow_format or not blank_edges:
        raise ValueError('Refusing format: existing/unknown data or explicit permission absent')
    return 'format_blank'


def all_zero(stream):
    while block := stream.read(4 * 1024 * 1024):
        if block.count(b'\0') != len(block):
            return False
    return True


def main():
    config = json.loads(Path('/etc/honeypot-infrastructure.json').read_text())
    device = Path(config['data_device'])
    if str(device) != '/dev/disk/azure/scsi1/lun0':
        raise ValueError('Only reviewed SCSI LUN0 supported; no /dev/sdX fallback')
    for _ in range(300):
        if device.exists():
            break
        time.sleep(2)
    else:
        raise ValueError('Managed LUN0 absent; refusing OS-disk fallback')
    real = device.resolve()
    info = json.loads(run('lsblk', '-J', '-o', 'NAME,TYPE,FSTYPE,MOUNTPOINTS', str(real)))['blockdevices'][0]
    if os.path.ismount(ROOT):
        mounted = run('findmnt', '-n', '-o', 'SOURCE', '--target', str(ROOT))
        if Path(mounted).resolve() != real:
            raise ValueError('Wrong disk already mounted at required path')
        return
    signatures = json.loads(run('wipefs', '--no-act', '--json', str(real)))['signatures']
    blank = False
    # Signature absence and zero edges do not prove absence of raw data. Inspect
    # the entire device only for an explicitly approved unformatted candidate.
    if not info.get('fstype') and not signatures and config['format_blank_data_disk']:
        with real.open('rb', buffering=0) as stream:
            blank = all_zero(stream)
    choice = action(info, signatures, config['format_blank_data_disk'], blank)
    if choice == 'format_blank':
        # No -F or wipefs erase; mkfs also refuses unexpected signatures.
        subprocess.run(['mkfs.ext4', '-L', 'honeypot-data', str(real)], check=True)
    uuid = run('blkid', '-s', 'UUID', '-o', 'value', str(real))
    if not uuid or any(c not in '0123456789abcdefABCDEF-' for c in uuid):
        raise ValueError('Missing/invalid filesystem UUID')
    ROOT.mkdir(mode=0o700, exist_ok=True)
    if any(ROOT.iterdir()):
        raise ValueError('Mountpoint has OS-disk files; manual review required')
    fstab = Path('/etc/fstab')
    text = fstab.read_text()
    entry = f'UUID={uuid} {ROOT} ext4 defaults,nodev,nosuid,x-systemd.device-timeout=120s 0 2'
    existing = [line for line in text.splitlines() if not line.startswith('#') and len(line.split()) > 1 and line.split()[1] == str(ROOT)]
    if existing and existing != [entry]:
        raise ValueError('Conflicting persistent mount entry')
    if not existing:
        with fstab.open('a') as stream:
            stream.write('\n' + entry + '\n')
    subprocess.run(['mount', str(ROOT)], check=True)
    if not os.path.ismount(ROOT) or Path(run('findmnt', '-n', '-o', 'SOURCE', '--target', str(ROOT))).resolve() != real:
        raise ValueError('Managed data disk mount verification failed')
    os.chmod(ROOT, 0o700)
    print('Managed LUN0 mounted; no application marker or key generated')


if __name__ == '__main__':
    main()
