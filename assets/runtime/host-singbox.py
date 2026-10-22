#!/usr/bin/env python3
"""Own the workstation's private host proxy, without altering Clash."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse
import uuid

BASE = Path(@@STATE_JSON@@)
BIN = Path(@@SINGBOX_JSON@@)
CONFIG = BASE / 'us-workstation-singbox.json'
CREDS = BASE / 'us-workstation-guest-socks'
PID = BASE / 'host-singbox.pid'
LOG = BASE / 'us-workstation-singbox.log'
LINK = Path(@@NODE_JSON@@)
VERSION = 'sing-box version 1.14.3'


class Failure(Exception):
    pass


def run(args, timeout=20):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


def require(ok, message):
    if not ok:
        raise Failure(message)


def private_read(path):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid(), 'Private input must be an owned regular file.')
    require(stat.S_IMODE(s.st_mode) == 0o600, 'Private input permissions must be 600.')
    return path.read_text()


def write_private(path, value):
    data = json.dumps(value, indent=2, sort_keys=True) + '\n'
    if path.exists():
        require(not path.is_symlink(), 'Refusing a symlink for private state.')
        if private_read(path) == data:
            return False
    fd, name = tempfile.mkstemp(prefix='.us-workstation-', dir=BASE)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return True


def route_info(*args):
    result = run(['/sbin/route', '-n', 'get', *args])
    if result.returncode:
        return {}
    return dict(re.findall(r'^\s*([a-z]+):\s*(.*?)\s*$', result.stdout, re.M))


def physical_route():
    result = run(['/usr/sbin/networksetup', '-listallhardwareports'])
    require(result.returncode == 0, 'Cannot enumerate physical network interfaces.')
    devices = re.findall(r'^Device: (en\d+)$', result.stdout, re.M)
    preferred = route_info('default').get('interface')
    if preferred in devices:
        devices.remove(preferred)
        devices.insert(0, preferred)
    for device in devices:
        info = route_info('-ifscope', device, 'default')
        if info.get('interface') != device:
            continue
        try:
            gateway = str(ipaddress.IPv4Address(info.get('gateway', '')))
        except ValueError:
            continue
        return device, gateway
    raise Failure('No physical IPv4 default gateway is available.')


def node():
    raw = private_read(LINK).strip()
    require('X25519MLKEM768' not in raw, 'Unexpected node handshake option.')
    link = urlparse(raw)
    require(link.scheme == 'vless' and link.port == 443, 'Node protocol or port does not match the contract.')
    params = parse_qs(link.query, keep_blank_values=True)
    expected = {'encryption': 'none', 'security': 'reality', 'type': 'tcp', 'flow': 'xtls-rprx-vision', 'fp': 'chrome', 'sni': 'www.cloudflare.com'}
    require(all(params.get(k) == [v] for k, v in expected.items()), 'Node protocol fields do not match the contract.')
    address = str(ipaddress.IPv4Address(link.hostname))
    user = str(uuid.UUID(link.username))
    public_key = params.get('pbk', [''])[0]
    short_id = params.get('sid', [''])[0]
    require(bool(re.fullmatch(r'[A-Za-z0-9_-]{43}', public_key)), 'Invalid REALITY public key encoding.')
    require(bool(re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,8}', short_id)), 'Invalid REALITY short id encoding.')
    return address, user, public_key, short_id


def credentials():
    if CREDS.exists():
        value = json.loads(private_read(CREDS))
        require(set(value) == {'username', 'password'}, 'Unexpected guest credential schema.')
        require(all(isinstance(v, str) and len(v) >= 16 for v in value.values()), 'Invalid guest credentials.')
        return value
    value = {'username': 'guest-' + secrets.token_hex(12), 'password': secrets.token_urlsafe(36)}
    write_private(CREDS, value)
    return value


def ensure_route(address, interface, gateway):
    info = route_info(address)
    if info.get('interface') == interface and info.get('gateway') == gateway and info.get('destination') == address:
        return
    verb = 'change' if info.get('destination') == address else 'add'
    command = shlex.join(['/sbin/route', '-n', verb, '-host', address, gateway]) + ' >/dev/null 2>&1'
    script = 'do shell script ' + json.dumps(command) + ' with administrator privileges'
    result = run(['/usr/bin/osascript', '-e', script], timeout=180)
    require(result.returncode == 0, 'The dedicated VPS route could not be installed with administrator privileges.')
    info = route_info(address)
    require(info.get('interface') == interface and info.get('gateway') == gateway and info.get('destination') == address,
            'The dedicated route is not using the physical interface.')


def active_pid():
    require(not PID.is_symlink(), 'Refusing a symlink pid file.')
    if not PID.exists():
        return None
    pid = int(PID.read_text().strip())
    result = run(['/bin/ps', '-p', str(pid), '-o', 'command='])
    if result.returncode:
        return None
    expected = f'{BIN} run -c {CONFIG}'
    require(result.stdout.strip() == expected, 'Recorded proxy pid belongs to another command; refusing to touch it.')
    return pid


def listening(port):
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(('127.0.0.1', port)) == 0


def check_config(config):
    fd, name = tempfile.mkstemp(prefix='.us-singbox-check-', suffix='.json', dir=BASE)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(config, stream)
        result = run([str(BIN), 'check', '-c', name])
        require(result.returncode == 0, 'Official sing-box rejected the generated host configuration (details suppressed to protect node data).')
    finally:
        os.unlink(name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare-only', action='store_true', help='Validate and save configuration; do not change routes or start processes.')
    args = parser.parse_args()
    os.umask(0o077)
    BASE.mkdir(exist_ok=True)
    lock = open(BASE / 'us-workstation-host.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    version = run([str(BIN), 'version'])
    require(version.returncode == 0 and version.stdout.splitlines()[0] == VERSION, 'Official host sing-box 1.14.3 is required.')
    creds = credentials()
    configured = LINK.exists() and bool(private_read(LINK).strip())
    require(configured, 'A private node file is mandatory; refusing to start unconfigured.')
    if not configured:
        config = {'log': {'level': 'warn'}, 'inbounds': [
            {'type': 'socks', 'tag': 'browser-socks-in', 'listen': '127.0.0.1', 'listen_port': @@PROBE_PORT@@},
            {'type': 'socks', 'tag': 'guest-socks-in', 'listen': '127.0.0.1', 'listen_port': @@SOCKS_PORT@@, 'users': [creds]},
        ], 'route': {'rules': [{'action': 'reject'}]}}
    else:
        interface, gateway = physical_route()
        address, user, public_key, short_id = node()
        config = {
            'log': {'level': 'warn'},
            'inbounds': [
                {'type': 'socks', 'tag': 'browser-socks-in', 'listen': '127.0.0.1', 'listen_port': @@PROBE_PORT@@},
                {'type': 'socks', 'tag': 'guest-socks-in', 'listen': '127.0.0.1', 'listen_port': @@SOCKS_PORT@@, 'users': [creds]},
            ],
            'outbounds': [{'type': 'vless', 'tag': 'vps', 'server': address, 'server_port': 443,
                           'uuid': user, 'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp',
                           'bind_interface': interface,
                           'tls': {'enabled': True, 'server_name': 'www.cloudflare.com',
                                   'utls': {'enabled': True, 'fingerprint': 'chrome'},
                                   'reality': {'enabled': True, 'public_key': public_key, 'short_id': short_id}}}],
            'route': {'final': 'vps'},
        }
    check_config(config)
    unchanged = CONFIG.exists() and json.loads(private_read(CONFIG)) == config
    pid = active_pid()
    if args.prepare_only:
        require(not pid or unchanged, 'Cannot replace configuration beneath a running proxy in prepare-only mode.')
        write_private(CONFIG, config)
        print('host_config=valid\nhost_version=1.14.3')
        return
    if configured:
        ensure_route(address, interface, gateway)
    state_summary = "physical_route=verified" if configured else "node=unconfigured;egress=blocked"
    if pid and unchanged:
        require(listening(@@PROBE_PORT@@) and listening(@@SOCKS_PORT@@), 'Proxy process exists but its listeners are unavailable.')
        print('host_proxy=unchanged\nhost_version=1.14.3\n' + state_summary)
        return
    if pid:
        os.kill(pid, signal.SIGTERM)
        for _ in range(100):
            if run(['/bin/ps', '-p', str(pid), '-o', 'pid=']).returncode:
                break
            time.sleep(0.1)
        else:
            raise Failure('Existing proxy did not stop; refusing to start another one.')
    require(not listening(@@PROBE_PORT@@) and not listening(@@SOCKS_PORT@@), 'A required SOCKS port is occupied by another process.')
    write_private(CONFIG, config)
    require(not LOG.is_symlink(), 'Refusing a symlink log file.')
    with open(LOG, 'a') as log:
        os.chmod(LOG, 0o600)
        child = subprocess.Popen([str(BIN), 'run', '-c', str(CONFIG)], stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=log, start_new_session=True)
    PID.write_text(str(child.pid) + '\n')
    os.chmod(PID, 0o600)
    for _ in range(100):
        require(child.poll() is None, 'Host sing-box exited; inspect its private log without publishing node data.')
        if listening(@@PROBE_PORT@@) and listening(@@SOCKS_PORT@@):
            print('host_proxy=running\nhost_version=1.14.3\n' + state_summary)
            return
        time.sleep(0.1)
    child.terminate()
    raise Failure('Host sing-box listeners did not become ready.')


if __name__ == '__main__':
    try:
        main()
    except Failure as error:
        sys.exit(str(error))
    except Exception as error:
        # Never stringify exceptions carrying parsed URLs or configuration.
        sys.exit(f'Host proxy operation failed ({type(error).__name__}); private values suppressed.')
