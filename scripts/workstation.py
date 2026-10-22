#!/usr/bin/env python3
"""Isolated macOS workstation lifecycle; no third-party Python dependencies."""
import argparse
import base64
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = {'profile', 'guest_user', 'limactl', 'limactl_sha256', 'singbox', 'singbox_sha256',
            'ipsw', 'ipsw_sha256', 'node_file', 'expected_exit_ipv4', 'probe_port', 'socks_port',
            'host_proxy_probe_port', 'shares'}
HEX = re.compile(r'[a-f0-9]{64}')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def private_json(path, value):
    path = Path(path)
    require(not path.is_symlink(), 'Refusing symlink state file')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + '.' + secrets.token_hex(6))
    with tmp.open('x') as f:
        os.chmod(tmp, 0o600)
        json.dump(value, f, indent=2)
        f.write('\n')
    tmp.replace(path)


def load(path):
    p = Path(path).expanduser().absolute()
    st = p.lstat()
    require(p.is_file() and not p.is_symlink() and st.st_uid == os.getuid() and st.st_mode & 0o777 == 0o600,
            'Profile must be an owned regular file with mode 600')
    c = json.loads(p.read_text())
    require(set(c) == REQUIRED, 'Profile fields do not match examples/profile.json')
    require(bool(re.fullmatch(r'[a-z][a-z0-9-]{2,39}', c['profile'])), 'Invalid profile name')
    require(bool(re.fullmatch(r'[a-z][a-z0-9_]{0,30}', c['guest_user'])), 'Invalid guest user')
    require(c['guest_user'] not in ('root', 'daemon', 'nobody'), 'Use an ordinary guest user')
    ipaddress.IPv4Address(c['expected_exit_ipv4'])
    for k in ('limactl', 'singbox', 'ipsw', 'node_file'):
        raw_path = Path(c[k]).expanduser()
        require(k != 'node_file' or not raw_path.is_symlink(), 'Node input cannot be a symlink')
        c[k] = str(raw_path.resolve())
    for k in ('limactl_sha256', 'singbox_sha256', 'ipsw_sha256'):
        require(bool(HEX.fullmatch(c[k])), 'An explicit SHA-256 pin is required')
    for k in ('probe_port', 'socks_port'):
        require(type(c[k]) is int and 1024 <= c[k] <= 65535, 'Invalid loopback port')
    require(c['probe_port'] != c['socks_port'], 'Ports must differ')
    hp = c['host_proxy_probe_port']
    require(hp is None or (type(hp) is int and 1024 <= hp <= 65535 and hp not in (c['probe_port'], c['socks_port'])), 'Invalid host proxy comparison port')
    require(isinstance(c['shares'], list), 'shares must be a list')
    mounts = []
    for share in c['shares']:
        require(set(share) == {'source', 'target', 'writable'}, 'Invalid share fields')
        require(type(share['writable']) is bool, 'writable must be boolean')
        share['source'] = str(Path(share['source']).expanduser().resolve())
        require(Path(share['source']).is_dir(), 'Share source must exist')
        t = PurePosixPath(share['target'])
        require(t.is_absolute() and '..' not in t.parts and str(t).startswith('/Users/' + c['guest_user'] + '/'), 'Share target must be below guest home')
        require(not any(t == x or t in x.parents or x in t.parents for x in mounts), 'Overlapping share targets are not supported')
        require(t.name not in ('.ssh', '.config', '.local'), 'Do not replace guest private service directories')
        mounts.append(t)
    return c


class Workstation:
    def __init__(self, config):
        self.c = config
        self.state = (Path.home() / '.local/share/macvm-skill' / config['profile']).resolve()
        self.lima = self.state / 'lima'
        self.runtime = self.state / 'runtime'
        self.env = dict(os.environ, LIMA_HOME=str(self.lima))
        for s in config['shares']:
            source = Path(s['source'])
            for private in (self.state, Path(config['node_file']), Path.home() / '.ssh'):
                private = private.resolve()
                require(source != private and source not in private.parents,
                        'Share source exposes private state, node file or host SSH keys')
        self.receipt = self.state / 'accepted.json'

    def run(self, args, timeout=30, **kwargs):
        return subprocess.run([str(a) for a in args], capture_output=True, timeout=timeout, **kwargs)

    def lima_cmd(self, args, timeout=60):
        return self.run([self.c['limactl'], *args], env=self.env, timeout=timeout)

    def guest(self, args, timeout=30, data=None):
        return self.run([self.c['limactl'], 'shell', '--workdir', '/', self.c['profile'], *args],
                        env=self.env, timeout=timeout, input=data)

    def checked_guest(self, args, timeout=30, data=None):
        r = self.guest(args, timeout, data)
        require(r.returncode == 0, 'Guest command failed; private output withheld')
        return r.stdout

    def script(self, name, *args, timeout=180):
        r = self.run([sys.executable, self.runtime / 'scripts' / name, *args], timeout=timeout)
        require(r.returncode == 0, name + ' failed; see local private audit report')
        return r.stdout

    def fingerprint(self):
        h = hashlib.sha256(json.dumps(self.c, sort_keys=True).encode())
        for folder in ('scripts', 'assets'):
            for p in sorted((ROOT / folder).rglob('*')):
                if p.is_file() and '__pycache__' not in p.parts:
                    h.update(str(p.relative_to(ROOT)).encode()); h.update(p.read_bytes())
        h.update(Path(self.c['node_file']).read_bytes())
        return h.hexdigest()

    def prerequisites(self, image=False):
        require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'Requires Apple Silicon macOS host')
        for key, version in [('limactl', '2.3.0-beta.1'), ('singbox', '1.14.3')]:
            require(digest(self.c[key]) == self.c[key + '_sha256'], key + ' checksum mismatch')
            r = self.run([self.c[key], '--version' if key == 'limactl' else 'version'])
            require(r.returncode == 0 and version in r.stdout.decode(), key + ' version mismatch')
        if image:
            require(digest(self.c['ipsw']) == self.c['ipsw_sha256'], 'Complete IPSW checksum mismatch')
        n = Path(self.c['node_file']); st = n.lstat()
        require(n.is_file() and not n.is_symlink() and st.st_uid == os.getuid() and st.st_mode & 0o777 == 0o600,
                'Node input must be a private regular file, mode 600')
        require(n.read_text().strip().startswith('vless://'), 'A user-provided VLESS node is required')

    def render(self):
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)
        target = self.runtime / 'scripts'; target.mkdir(parents=True, exist_ok=True)
        values = {'GUEST_USER':self.c['guest_user'], 'PROBE_PORT':str(self.c['probe_port']),
            'SOCKS_PORT':str(self.c['socks_port']), 'HOST_PROXY_PORT':str(self.c['host_proxy_probe_port'] or 7890), 'STATE_JSON':json.dumps(str(self.state)),
            'SINGBOX_JSON':json.dumps(self.c['singbox']), 'NODE_JSON':json.dumps(self.c['node_file']),
            'EXPECTED_EXIT_JSON':json.dumps(self.c['expected_exit_ipv4']),
            'SSH_CONFIG_JSON':json.dumps(str(self.lima / self.c['profile'] / 'ssh.config')),
            'SSH_HOST_JSON':json.dumps('lima-' + self.c['profile']),
            'CLIPBOARD_LABEL_JSON':json.dumps('local.macvm-skill.' + self.c['profile'] + '.clipboard')}
        for p in (ROOT / 'assets/runtime').iterdir():
            s = p.read_text()
            for k,v in values.items(): s = s.replace('@@'+k+'@@', v)
            require(not re.search(r'@@[A-Z_]+@@', s), 'Unresolved runtime template')
            (target / p.name).write_text(s); (target / p.name).chmod(0o700)
        wrapper = '#!/bin/sh\nset -eu\nexport LIMA_HOME=' + shlex.quote(str(self.lima)) + '\n'
        wrapper += '[ "$1" = shell ] || exit 2\nshift\nexec ' + shlex.quote(self.c['limactl']) + ' shell --workdir / ' + shlex.quote(self.c['profile']) + ' "$@"\n'
        (target/'macos-vm.sh').write_text(wrapper);(target/'macos-vm.sh').chmod(0o700)
        vm = {'minimumLimaVersion':'2.3.0-beta.1','vmType':'vz','os':'Darwin','arch':'aarch64',
            'cpus':4,'memory':'6GiB','disk':'64GiB','timezone':'America/Los_Angeles',
            'user':{'name':self.c['guest_user'],'home':'/Users/'+self.c['guest_user'],'uid':501,'shell':'/bin/zsh','passwordlessSudo':False},
            'mounts':[{'location':s['source'],'mountPoint':s['target'],'writable':s['writable']} for s in self.c['shares']],
            'video':{'display':'default'},'ssh':{'forwardAgent':False,'loadDotSSHPubKeys':False},'propagateProxyEnv':False,
            'env':{k:'' for k in ('http_proxy','https_proxy','all_proxy','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')},
            'containerd':{'system':False,'user':False},'osOpts':{'Darwin':{'suppressFirstLoginSetup':True}},
            'images':[{'location':self.c['ipsw'],'arch':'aarch64','digest':'sha256:'+self.c['ipsw_sha256']}]}
        private_json(self.state/'instance.yaml', vm)  # JSON is valid YAML.

    def identity(self):
        raw = self.checked_guest(['ioreg','-rd1','-c','IOPlatformExpertDevice'])
        match = re.search(rb'"IOPlatformUUID"\s*=\s*"([A-Fa-f0-9-]+)"',raw)
        require(match is not None, 'Cannot identify this guest')
        return hashlib.sha256(match[1]).hexdigest()

    def invalidate(self):
        for name in ('accepted.json', 'system-checks.json', 'pending-ui.json'):
            (self.state/name).unlink(missing_ok=True)

    def quarantine(self):
        self.invalidate()
        # Root control leaves PF enabled. If it cannot stop the proxy, stop the VM normally.
        try:
            r = self.guest(['sudo','-n','/usr/local/libexec/us-workstation/control','stop'],timeout=15)
            if r.returncode == 0:return
        except Exception:pass
        try:
            r = self.lima_cmd(['stop',self.c['profile']],timeout=90)
            require(r.returncode==0,'Could not stop unverified VM')
        except Exception:
            print('ATTENTION: containment could not be confirmed; VM may still be running. Do not use it.',file=sys.stderr)

    def proxy(self):
        self.script('host-singbox.py')
        r=self.run(['curl','--noproxy','','--proxy',f"socks5h://127.0.0.1:{self.c['probe_port']}",'-fsS','--max-time','12','https://www.cloudflare.com/cdn-cgi/trace'])
        ips=re.findall(rb'^ip=(.*)$',r.stdout,re.M)
        require(r.returncode==0 and ips==[self.c['expected_exit_ipv4'].encode()], 'Host proxy exit differs from the explicitly expected address')

    def bootstrap(self):
        require(not (self.lima/self.c['profile']).exists(), 'Instance exists; bootstrap never overwrites or recreates it')
        self.prerequisites(image=True);self.render();self.proxy();self.invalidate()
        require(self.lima_cmd(['create','--name='+self.c['profile'],str(self.state/'instance.yaml')],timeout=180).returncode==0,'Lima create failed')
        require(self.lima_cmd(['start','--tty=false',self.c['profile']],timeout=3600).returncode==0,'Bootstrap failed')
        print('BOOTSTRAP ONLY: no acceptance. Do not browse or sign in until network installation and accept pass.')
        self.script('macos-network-stage.py','--open')

    def network(self, faults=False):
        args=['--faults'] if faults else []
        r=self.run([sys.executable,self.runtime/'scripts/macos-network-check.py',*args],timeout=240)
        try: report=json.loads(r.stdout)
        except ValueError:raise RuntimeError('Network probe produced no valid report')
        private_json(self.state/'network-last.json',report)
        private_json(self.state/'audit'/('network-'+str(time.time_ns())+'.json'), report)
        blocked = {'forced_ipv4_blocked','ipv6_direct_blocked','host_socks_user_blocked','host_clash_blocked','host_dns_blocked'}
        online = blocked | {'https_available','dns_available','matches_original_proxy_exit','matches_configured_node_exit','host_node_bound_to_physical_interface','host_node_uses_dedicated_physical_route'}
        offline = blocked | {'https_blocked','dns_blocked'}
        required = {'online':online}
        if faults: required.update(guest_proxy_stopped=offline, host_upstream_blocked=offline, restored=online)
        require(r.returncode==0 and isinstance(report,dict) and set(report)==set(required) and all(isinstance(report[k],dict) and set(report[k])==fields and all(v is True for v in report[k].values()) for k,fields in required.items()), 'Mandatory network checks failed or missing')
        return report

    def firewall(self):
        raw=self.checked_guest(['sudo','-n','/usr/local/libexec/us-workstation/control','audit']).decode()
        require('Status: Enabled' in raw and 'anchor "us-workstation"' in raw and 'block drop quick all' in raw,'PF protection is missing')
        require('user = 0' in raw and f"port = {self.c['socks_port']}" in raw,'Restricted host channel missing')
        # Match protocol inactivity on the actual Ethernet service through structured plist parsing.
        import plistlib
        p=plistlib.loads(self.checked_guest(['cat','/Library/Preferences/SystemConfiguration/preferences.plist']))
        services=[v for v in p['NetworkServices'].values() if v.get('Interface',{}).get('DeviceName')=='en0']
        require(len(services)==1 and all(services[0].get(k,{}).get('__INACTIVE__') is True for k in ('IPv4','IPv6')),'Ethernet can activate before PF at boot')
        for name,installed in [('macos-network-control.sh','control'),('macos-network-run.sh','run')]:
            require(digest(self.runtime/'scripts'/name) in raw, 'Installed network script does not match this package: '+installed)
        require((self.state/'expected-guest-config.sha256').read_text().strip() in raw, 'Installed guest config differs from the staged restricted config')
        return {'pf_enabled':True,'ethernet_ipv4_ipv6_inactive':True,'installed_script_hashes_match':True}

    def shares(self):
        outcomes=[]
        for s in self.c['shares']:
            name='.macvm-check-'+secrets.token_hex(12); p=Path(s['source'])/name
            # Read-only content check is also tested; host owns/removes only its unique marker.
            token=secrets.token_hex(16)
            with p.open('x') as f:f.write(token)
            try:
                vols=self.checked_guest(['find','/Volumes/My Shared Files','-maxdepth','2','-name',name]).decode().splitlines()
                require(len(vols)==1,'Shared volume missing or ambiguous')
                actual=str(PurePosixPath(vols[0]).parent); target=s['target']
                command='mkdir -p "$1"; if [ ! -e "$2" ] && [ ! -L "$2" ]; then ln -s "$3" "$2"; fi; test "$(cat "$2/$4")" = "$5"'
                self.checked_guest(['sh','-c',command,'share',str(PurePosixPath(target).parent),target,actual,name,token])
                write=self.guest(['sh','-c','printf %s guest >> "$1"','share',target+'/'+name])
                if s['writable']:
                    require(write.returncode==0 and p.read_text()==token+'guest','Shared write did not reach host')
                else:require(write.returncode!=0 and p.read_text()==token,'Read-only share was writable')
                outcomes.append({'index':len(outcomes),'read':True,'write_policy':True})
            finally:p.unlink(missing_ok=True)
        return outcomes

    def clipboard(self):
        # Installed per profile. Existing clipboard contents remain in memory and are restored.
        import importlib.util
        agents = self.run(['launchctl','list'])
        require(agents.returncode == 0, 'Cannot check existing clipboard bridges')
        own = 'local.macvm-skill.' + self.c['profile'] + '.clipboard'
        labels = [line.split()[-1] for line in agents.stdout.decode().splitlines() if line.split()]
        require(not any(label != own and (label.startswith('local.macvm-skill.') and label.endswith('.clipboard') or label == 'local.macos-workstation.clipboard') for label in labels), 'Another workstation clipboard bridge is loaded; explicitly stop it before candidate clipboard acceptance')
        spec=importlib.util.spec_from_file_location('bridge',self.runtime/'scripts/macos-clipboard.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        host=module.call(False,'read'); guest=module.call(True,'read')
        require('items' in host and 'items' in guest,'Cannot safely preserve clipboard; finish manually after clearing confidential clipboard entries')
        # Stop the bridge to test each endpoint without a polling race; restore then re-enable.
        self.script('macos-clipboard.py','off')
        try:
            payload={'items':[{'public.utf8-plain-text':base64.b64encode(('clipboard-测试-'+secrets.token_hex(8)).encode()).decode()}]}
            module.call(True,'write',payload=payload); read=module.call(True,'read')
            require(read.get('items')==payload['items'],'Guest clipboard round trip failed')
            module.call(False,'write',payload=read)
            require(module.call(False,'read').get('items')==payload['items'],'Host clipboard round trip failed')
        finally:
            module.call(False,'write',payload=host);module.call(True,'write',payload=guest)
            self.script('macos-clipboard.py','on')
        return {'endpoint_roundtrip':True,'ui_bidirectional_confirmation':'required-separately'}

    def browser(self):
        collected=[]; done=threading.Event(); token=secrets.token_hex(16)
        page=(ROOT/'assets/browser-check.html').read_bytes()
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                if self.path!='/'+token+'/':self.send_error(404);return
                self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.end_headers();self.wfile.write(page)
            def do_POST(self):
                if self.path!='/'+token+'/report':self.send_error(404);return
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<65536:self.send_error(413);return
                collected.append(json.loads(self.rfile.read(length)));self.send_response(200);self.end_headers();done.set()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);port=server.server_port
        threading.Thread(target=server.serve_forever,daemon=True).start()
        # Start a dedicated tunnel, never a public listener or debug port.
        process=subprocess.Popen(['/usr/bin/ssh','-F',str(self.lima/self.c['profile']/'ssh.config'),'-S','none','-o','ControlMaster=no','-o','ExitOnForwardFailure=yes','-N','-R',f'127.0.0.1:{port}:127.0.0.1:{port}','lima-'+self.c['profile']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            time.sleep(1);require(process.poll() is None,'Loopback browser collector unavailable')
            self.checked_guest(['open','-a','Google Chrome',f'http://127.0.0.1:{port}/{token}/'])
            require(done.wait(90),'Browser collection timed out; sign in to guest desktop and install Chrome first')
        finally:
            server.shutdown();server.server_close();process.terminate();process.wait(timeout=10)
        r=collected[0];expected=self.c['expected_exit_ipv4']
        require(r['network']['https'].get('ok') is True and r['network']['https'].get('ip')==expected,'Browser HTTPS exit mismatch')
        require(len(r.get('webrtc',[]))==2,'Missing STUN probes')
        for s in r['webrtc']:
            candidates=[x['candidate'].split() for x in s['candidates']]
            require(any('srflx' in x and x[4]==expected for x in candidates),'STUN public exit missing or mismatched')
            require(all(x[4]==expected if 'srflx' in x else x[4].endswith('.local') for x in candidates),'Unexpected ICE address exposed')
        require(all(r['webgl'][k].get('available') is True for k in ('webgl','webgl2')),'WebGL compatibility failed')
        # Store graphics facts, booleans and errors, not IPs or random ICE identifiers.
        return {'https_expected':True,'webrtc_expected':True,'webgl':r['webgl'],'webgpu':r.get('webgpu'),
                'stun_errors':[s['errors'] for s in r['webrtc']]}

    def host_comparison(self):
        port=self.c['host_proxy_probe_port']
        if port is None:
            ps=self.run(['ps','-axo','comm=']).stdout.decode().lower()
            require('mihomo' not in ps and 'clash' not in ps,'Host proxy detected; configure its comparison port')
            return {'host_proxy_present':False}
        r=self.run(['curl','--noproxy','','--proxy',f'http://127.0.0.1:{port}','-fsS','--max-time','12','https://www.cloudflare.com/cdn-cgi/trace'])
        ips=re.findall(rb'^ip=(.*)$',r.stdout,re.M)
        require(r.returncode==0 and len(ips)==1,'Cannot verify host proxy comparison exit')
        require(ips[0].decode()!=self.c['expected_exit_ipv4'],'Host proxy and dedicated exits are indistinguishable')
        return {'host_proxy_present':True,'exit_distinct':True}

    def accept(self):
        self.invalidate();self.prerequisites();self.render();self.proxy()
        uid=self.identity();report={'guest':uid,'fingerprint':self.fingerprint(),'time':time.time()}
        self.checked_guest(['sudo','-n','/usr/local/libexec/us-workstation/control','start'])
        time.sleep(3)
        report['firewall']=self.firewall();report['shares']=self.shares()
        report['host_comparison']=self.host_comparison();report['network_faults']=self.network(True)
        require(self.lima_cmd(['stop',self.c['profile']],timeout=120).returncode==0,'Normal cold stop failed; no force stop attempted')
        self.proxy()
        require(self.lima_cmd(['start','--tty=false',self.c['profile']],timeout=240).returncode==0,'Cold restart failed')
        require(self.identity()==uid,'Guest identity changed during acceptance')
        report['cold_network']=self.network();report['cold_firewall']=self.firewall();report['cold_shares']=self.shares()
        private_json(self.state/'system-checks.json',report)
        print('System checks passed; finish desktop login, then run finish-acceptance. Not yet accepted.')

    def finish(self):
        report=json.loads((self.state/'system-checks.json').read_text())
        require(report['guest']==self.identity() and report['fingerprint']==self.fingerprint() and time.time()-report['time']<3600,
                'System checks missing, stale or for another configuration/guest')
        report['final_host_comparison']=self.host_comparison();report['final_firewall']=self.firewall()
        report['final_network']=self.network();report['browser']=self.browser();report['clipboard']=self.clipboard()
        private_json(self.state/'pending-ui.json',report)
        print('Automated checks passed. Ask user to confirm real bidirectional clipboard after cold start, then confirm-ui. Not yet accepted.')

    def ready(self):
        r=json.loads(self.receipt.read_text())
        require(r['guest']==self.identity() and r['fingerprint']==self.fingerprint(),'Acceptance belongs to another guest or configuration; rerun accept')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    parser.add_argument('command',choices=['validate','bootstrap','install-network','accept','finish-acceptance','confirm-ui','start','stop','shell','check','rebuild'])
    parser.add_argument('--from-config',help='Required for rebuild; existing profile remains untouched')
    parser.add_argument('--reuse-node',action='store_true',help='Only for an explicitly requested reuse during rebuild')
    parser.add_argument('guest_args',nargs='*')
    args=parser.parse_args();os.umask(0o077)
    w=Workstation(load(args.config));cmd=args.command
    if cmd=='validate':
        print('Profile structure valid. Runtime, downloads and VM acceptance not tested.');return
    if cmd=='rebuild':
        require(args.from_config is not None,'Rebuild requires --from-config')
        old=Workstation(load(args.from_config))
        require(old.state!=w.state,'Rebuild must use a fresh profile; old disk is never overwritten')
        require(not {old.c['probe_port'],old.c['socks_port']}&{w.c['probe_port'],w.c['socks_port']},'Rebuild must use independent host ports')
        require(not w.state.exists(),'Rebuild target state must be new')
        if not args.reuse_node:
            require(Path(old.c['node_file']).read_text().strip()!=Path(w.c['node_file']).read_text().strip() and old.c['expected_exit_ipv4']!=w.c['expected_exit_ipv4'],'New private node and exit required unless reuse was explicitly requested')
        w.bootstrap();print('Old instance retained. New instance must pass accept/finish-acceptance/confirm-ui before cutover.');return
    if cmd=='bootstrap':w.bootstrap();return
    if cmd=='stop':
        require(w.lima_cmd(['stop',w.c['profile']],timeout=120).returncode==0,'Normal stop failed; force stop requires separate user approval');return
    require((w.lima/w.c['profile']).is_dir(),'No such managed instance')
    try:
        w.prerequisites();w.render()
        if cmd=='install-network':w.invalidate();w.proxy();w.script('macos-network-stage.py','--open');return
        if cmd=='accept':w.accept();return
        if cmd=='finish-acceptance':w.finish();return
        if cmd=='confirm-ui':
            r=json.loads((w.state/'pending-ui.json').read_text())
            require(r['guest']==w.identity() and r['fingerprint']==w.fingerprint() and time.time()-r['time']<3600,'UI evidence is stale or mismatched')
            w.firewall();w.host_comparison();w.network();r['clipboard']['ui_bidirectional_confirmation']=True;r['accepted_at']=time.time();private_json(w.receipt,r)
            print('ACCEPTED: this guest/configuration only.');return
        if cmd=='start':
            require(w.receipt.exists(),'Not accepted; use bootstrap/install-network and acceptance workflow')
            w.proxy();require(w.lima_cmd(['start','--tty=false',w.c['profile']],timeout=240).returncode==0,'Start failed')
        w.ready();w.proxy();w.firewall();w.network();w.host_comparison()
        if cmd=='shell':
            r=subprocess.run([w.c['limactl'],'shell','--workdir','/',w.c['profile'],*args.guest_args],env=w.env)
            raise SystemExit(r.returncode)
        print('Mandatory current network gate passed.')
    except (Exception, KeyboardInterrupt):
        w.quarantine();raise


if __name__=='__main__':
    try: main()
    except KeyboardInterrupt:sys.exit('Interrupted; verify guest state before using it.')
    except Exception as e:sys.exit(f'BLOCKED: {e}' if isinstance(e,RuntimeError) else f'BLOCKED: {type(e).__name__}; private details withheld')
