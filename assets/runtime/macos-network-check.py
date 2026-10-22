#!/usr/bin/env python3
"""Live acceptance for the isolated macOS candidate. Reports no credentials."""
import argparse
import json
import pathlib
import re
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
VM = [str(ROOT / 'scripts/macos-vm.sh'), 'shell']
CONTROL = ['sudo', '-n', '/usr/local/libexec/us-workstation/control']


def host_path_checks(guest_ip):
    """Check against the pinned node, not merely another possibly wrong exit."""
    result = {'matches_configured_node_exit': False, 'host_node_bound_to_physical_interface': False,
              'host_node_uses_dedicated_physical_route': False}
    try:
        config = json.loads((pathlib.Path(@@STATE_JSON@@) / 'us-workstation-singbox.json').read_text())
        node = next(x for x in config['outbounds'] if x.get('tag') == 'vps')
        interface = node.get('bind_interface', '')
        result['matches_configured_node_exit'] = bool(guest_ip) and guest_ip == @@EXPECTED_EXIT_JSON@@
        result['host_node_bound_to_physical_interface'] = bool(re.fullmatch(r'en\d+', interface))
        route = subprocess.run(['/sbin/route', '-n', 'get', node['server']],
                               capture_output=True, text=True, timeout=5)
        fields = dict(re.findall(r'^\s*([a-z]+):\s*(.*?)\s*$', route.stdout, re.M))
        result['host_node_uses_dedicated_physical_route'] = (route.returncode == 0
            and result['host_node_bound_to_physical_interface']
            and fields.get('interface') == interface and fields.get('destination') == node['server'])
    except (OSError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired):
        pass  # Report only booleans; never print private configuration or node credentials.
    return result


def guest(args, timeout=20):
    result = subprocess.run(VM + args, capture_output=True, text=True, timeout=timeout)
    if result.returncode in (126, 127, 255):
        raise RuntimeError('Guest probe could not execute; not a network block result.')
    return result


def checks(online):
    result = {}
    trace = guest(['curl', '--noproxy', '*', '-fsS', '--connect-timeout', '4', '--max-time', '10',
                   'https://www.cloudflare.com/cdn-cgi/trace'])
    result['https_available' if online else 'https_blocked'] = (trace.returncode == 0) if online else trace.returncode in (6, 7, 28)
    query = 'example.com' if online else f'uncached-{time.time_ns()}.example.com'
    dns = guest(['dig', '@172.19.0.2', query, '+time=3', '+tries=1'])
    result['dns_available' if online else 'dns_blocked'] = ('status: NOERROR' in dns.stdout and 'ANSWER: 0' not in dns.stdout) if online else dns.returncode == 9
    for name, command in {
        'forced_ipv4_blocked': ['curl', '--noproxy', '*', '--interface', 'en0', '-k', '-sS', '--max-time', '4', 'https://1.1.1.1/'],
        'ipv6_direct_blocked': ['curl', '--noproxy', '*', '-6', '-k', '-sS', '--max-time', '4', 'https://[2606:4700:4700::1111]/'],
        'host_socks_user_blocked': ['nc', '-z', '-G', '3', '192.168.5.2', '@@SOCKS_PORT@@'],
        'host_clash_blocked': ['nc', '-z', '-G', '3', '192.168.5.2', '@@HOST_PROXY_PORT@@'],
        'host_dns_blocked': ['dig', '@192.168.5.2', f'uncached-{time.time_ns()}.example.com', '+time=2', '+tries=1'],
    }.items():
        probe = guest(command)
        expected = {4, 6, 7, 28, 45} if command[0] == 'curl' else ({9} if command[0] == 'dig' else {1})
        result[name] = probe.returncode in expected
    if online and trace.returncode == 0:
        host = subprocess.run(['curl', '--proxy', 'socks5h://127.0.0.1:@@PROBE_PORT@@', '--noproxy', '',
                               '-fsS', '--max-time', '12', 'https://www.cloudflare.com/cdn-cgi/trace'],
                              capture_output=True, text=True, timeout=15)
        def ip(text):
            return next((x[3:] for x in text.splitlines() if x.startswith('ip=')), None)
        result['matches_original_proxy_exit'] = host.returncode == 0 and bool(ip(trace.stdout)) and ip(trace.stdout) == ip(host.stdout)
        result.update(host_path_checks(ip(trace.stdout)))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--faults', action='store_true', help='Temporarily stop guest proxy and block its host upstream; restore in finally.')
    args = parser.parse_args()
    report = {'online': checks(True)}
    if args.faults:
        for mode in ['guest_proxy_stopped', 'host_upstream_blocked']:
            enter, leave = ('stop', 'start') if mode == 'guest_proxy_stopped' else ('block-host', 'unblock-host')
            try:
                changed = guest(CONTROL + [enter])
                if changed.returncode:
                    raise RuntimeError('Cannot apply fault: ' + mode)
                time.sleep(2)
                report[mode] = checks(False)
            finally:
                restored = guest(CONTROL + [leave])
                if restored.returncode:
                    raise RuntimeError('Restore failed: ' + mode)
                time.sleep(5)
        report['restored'] = checks(True)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if all(all(section.values()) for section in report.values()) else 1)


if __name__ == '__main__':
    main()
