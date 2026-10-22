#!/usr/bin/env python3
"""Private, bidirectional clipboard bridge over the existing Lima SSH channel."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import plistlib
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
STATE = Path(@@STATE_JSON@@) / 'clipboard'
HELPER = ROOT / 'scripts/macos-clipboard.jxa'
GUEST_HELPER = '/Users/@@GUEST_USER@@/.local/libexec/macos-clipboard.jxa'


def call(guest, action, previous=-1, payload=None):
    args = ['/usr/bin/osascript', '-l', 'JavaScript', GUEST_HELPER if guest else str(HELPER), action, str(previous)]
    if guest:
        # A bounded dedicated SSH connection avoids retaining orphaned limactl
        # children while the VM shuts down or its management path is unavailable.
        config = Path(@@SSH_CONFIG_JSON@@)
        args = ['/usr/bin/ssh', '-F', str(config), '-S', 'none', '-o', 'ControlMaster=no',
                '-o', 'ConnectTimeout=3', '-o', 'ServerAliveInterval=3',
                '-o', 'ServerAliveCountMax=1', '-o', 'BatchMode=yes', @@SSH_HOST_JSON@@, '--'] + args
    result = subprocess.run(args, input=json.dumps(payload).encode() if payload is not None else None,
                            capture_output=True, timeout=8)
    if result.returncode:
        raise RuntimeError('clipboard endpoint unavailable')
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['run', 'status', 'on', 'off'])
    args = parser.parse_args()
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True)
    status = STATE / 'status.json'
    label = @@CLIPBOARD_LABEL_JSON@@
    domain = f'gui/{os.getuid()}'
    agent = Path.home() / 'Library/LaunchAgents' / (label + '.plist')
    if args.command == 'off':
        subprocess.run(['launchctl', 'disable', domain + '/' + label], check=True)
        subprocess.run(['launchctl', 'bootout', domain + '/' + label], capture_output=True)
        print('clipboard=disabled')
        return
    if args.command == 'on':
        subprocess.run([str(ROOT / 'scripts/macos-vm.sh'), 'shell', 'sh', '-c',
                        'mkdir -p /Users/@@GUEST_USER@@/.local/libexec; umask 077; cat > ' + GUEST_HELPER],
                       input=HELPER.read_bytes(), check=True)
        agent.parent.mkdir(parents=True, exist_ok=True)
        agent.write_bytes(plistlib.dumps({'Label': label, 'ProgramArguments': [sys.executable, str(Path(__file__).resolve()), 'run'],
            'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 5,
            'StandardOutPath': str(STATE / 'service.log'), 'StandardErrorPath': str(STATE / 'service.log')}))
        subprocess.run(['launchctl', 'enable', domain + '/' + label], check=True)
        if subprocess.run(['launchctl', 'print', domain + '/' + label], capture_output=True).returncode:
            subprocess.run(['launchctl', 'bootstrap', domain, str(agent)], check=True)
        print('clipboard=enabled')
        return
    if args.command == 'status':
        running = subprocess.run(['launchctl', 'print', domain + '/' + label], capture_output=True).returncode == 0
        print(status.read_text() if running and status.exists() else '{"state":"not-running"}')
        return
    counts = None
    transfers = 0
    def report(state):
        tmp = status.with_suffix('.tmp')
        tmp.write_text(json.dumps({'state': state, 'transfers': transfers, 'updated_at': time.time()}))
        tmp.replace(status)
    while True:
        try:
            if counts is None:
                # Establish a baseline; do not copy pre-existing clipboard contents on start/reconnect.
                counts = [call(False, 'read')['count'], call(True, 'read')['count']]
                report('ready')
            else:
                host, guest = call(False, 'read', counts[0]), call(True, 'read', counts[1])
                changed = [host['count'] != counts[0], guest['count'] != counts[1]]
                counts = [host['count'], guest['count']]
                # If both changed within this interval, the host wins deterministically.
                source = 0 if changed[0] else (1 if changed[1] else None)
                if source is not None:
                    data = [host, guest][source]
                    if 'items' in data:
                        counts[1-source] = call(source == 0, 'write', payload=data)['count']
                        transfers += 1
                report('ready')
            time.sleep(0.8)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            # Never log endpoint stdout, clipboard payloads, or exception bodies.
            counts = None
            report('waiting-for-guest')
            time.sleep(3)


if __name__ == '__main__':
    main()
