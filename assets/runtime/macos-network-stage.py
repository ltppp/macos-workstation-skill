#!/usr/bin/env python3
"""Stage the macOS guest network installer using the existing host proxy.

Credentials travel over Lima SSH, never through the work share or repository.
Run this only after scripts/host-singbox.sh has prepared the existing node.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
HOME = Path.home()
VM = [str(ROOT / 'scripts/macos-vm.sh'), 'shell']
STAGE = '/Users/@@GUEST_USER@@/.us-network-stage'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--open', action='store_true', help='Open the guest Terminal for local sudo authentication.')
    args = parser.parse_args()
    os.umask(0o077)
    private = Path(@@STATE_JSON@@) / 'us-workstation-guest-socks'
    meta = private.lstat()
    if private.is_symlink() or meta.st_uid != os.getuid() or meta.st_mode & 0o777 != 0o600:
        raise RuntimeError('Host forwarding credential permissions must be 600.')
    creds = json.loads(private.read_text())
    if set(creds) != {'username', 'password'}:
        raise RuntimeError('Unexpected credential schema.')
    config = {
        'log': {'level': 'warn'},
        'dns': {'servers': [{'type': 'udp', 'tag': 'remote', 'server': '1.1.1.1', 'detour': 'host-proxy'}],
                'final': 'remote', 'strategy': 'ipv4_only'},
        'inbounds': [{'type': 'tun', 'tag': 'tun-in', 'interface_name': 'utun8',
                      'address': ['172.19.0.1/30'], 'mtu': 1400, 'auto_route': True,
                      'strict_route': True, 'stack': 'gvisor', 'route_exclude_address': ['192.168.5.2/32']}],
        'outbounds': [{'type': 'socks', 'tag': 'host-proxy', 'server': '192.168.5.2', 'server_port': @@SOCKS_PORT@@,
                       'version': '5', 'udp_over_tcp': {'enabled': True, 'version': 2},
                       'bind_interface': 'en0', **creds}],
        'route': {'default_interface': 'en0', 'final': 'host-proxy', 'rules': [
            {'protocol': 'dns', 'action': 'hijack-dns'},
            {'ip_cidr': ['198.18.0.0/15', '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12',
                         '169.254.0.0/16', 'fc00::/7', 'fe80::/10'], 'action': 'reject'}]},
    }
    binary = Path(@@SINGBOX_JSON@@)
    version = subprocess.run([str(binary), 'version'], capture_output=True, text=True, check=True)
    if version.stdout.splitlines()[0] != 'sing-box version 1.14.3':
        raise RuntimeError('Expected the existing official sing-box 1.14.3.')
    subprocess.run(VM + ['sh', '-c', f'umask 077; mkdir -p {STAGE}; chmod 700 {STAGE}'], check=True)
    def put(data, name):
        subprocess.run(VM + ['sh', '-c', f'umask 077; cat > {STAGE}/{name}'], input=data, check=True)
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(json.dumps(config).encode()); tmp.flush()
        check = subprocess.run([str(binary), 'check', '-c', tmp.name], capture_output=True)
        if check.returncode:
            raise RuntimeError('Configuration rejected; secret-bearing output suppressed.')
        put(json.dumps(config).encode(), 'config.json')
        (Path(@@STATE_JSON@@) / 'expected-guest-config.sha256').write_text(hashlib.sha256(json.dumps(config).encode()).hexdigest())
    for name in ['macos-network-install.sh', 'macos-network-run.sh', 'macos-network-control.sh']:
        put((ROOT / 'scripts' / name).read_bytes(), name)
    data = binary.read_bytes()
    put(data, 'sing-box')
    digest = subprocess.run(VM + ['shasum', '-a', '256', STAGE + '/sing-box'], capture_output=True, text=True, check=True)
    if digest.stdout.split()[0] != hashlib.sha256(data).hexdigest():
        raise RuntimeError('Guest binary transfer hash mismatch.')
    put(b'''#!/bin/bash
sudo /bin/bash /Users/@@GUEST_USER@@/.us-network-stage/macos-network-install.sh /Users/@@GUEST_USER@@/.us-network-stage
result=$?
printf '\\nInstaller exit code: %s\\n' "$result"
read -r -p 'Press Return to close. '
exit "$result"
''', 'Install-Network.command')
    subprocess.run(VM + ['sh', '-c', f'chmod 700 {STAGE}/*.sh {STAGE}/sing-box {STAGE}/Install-Network.command'], check=True)
    result = subprocess.run(VM + [STAGE + '/sing-box', 'check', '-c', STAGE + '/config.json'], capture_output=True)
    if result.returncode:
        raise RuntimeError('Guest configuration check failed; output suppressed.')
    print('stage=ready; binary_hash=verified; node_secrets_copied=false')
    if args.open:
        opened = subprocess.run(VM + ['open', '-a', 'Terminal', STAGE + '/Install-Network.command'], capture_output=True)
        print('installer_terminal=opened' if opened.returncode == 0 else 'installer_terminal=desktop-login-required; rerun install-network after login')


if __name__ == '__main__':
    main()
