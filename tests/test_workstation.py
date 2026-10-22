import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('workstation',ROOT/'scripts/workstation.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)

class WorkstationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.patch=patch.object(Path,'home',return_value=self.home);self.patch.start();self.addCleanup(self.patch.stop)
        share=self.home/'project';share.mkdir()
        self.c={'profile':'candidate-one','guest_user':'worker','limactl':str(self.home/'limactl'), 'limactl_sha256':'a'*64,
                'singbox':str(self.home/'singbox'),'singbox_sha256':'b'*64,'ipsw':str(self.home/'os.ipsw'), 'ipsw_sha256':'c'*64,
                'node_file':str(self.home/'private/node'),'expected_exit_ipv4':'192.0.2.10','probe_port':28080,'socks_port':28081,
                'host_proxy_probe_port':7890,'shares':[{'source':str(share),'target':'/Users/worker/work','writable':True}]}
        node=Path(self.c['node_file']);node.parent.mkdir();node.write_text('TEST-ONLY-NODE');node.chmod(0o600)
        self.p=self.home/'profile.json';self.save()
    def save(self):
        self.p.write_text(json.dumps(self.c));self.p.chmod(0o600)
    def test_private_profile_required(self):
        self.p.chmod(0o644)
        with self.assertRaises(RuntimeError):w.load(self.p)
    def test_shell_injection_username_rejected(self):
        self.c['guest_user']='worker; touch /tmp/bad';self.save()
        with self.assertRaises(RuntimeError):w.load(self.p)
    def test_overlapping_mounts_rejected(self):
        self.c['shares'].append(dict(self.c['shares'][0],target='/Users/worker/work/nested'));self.save()
        with self.assertRaises(RuntimeError):w.load(self.p)
    def test_no_private_data_sharing(self):
        self.c['shares'][0]['source']=str(self.home);self.save()
        with self.assertRaises(RuntimeError):w.Workstation(w.load(self.p))
    def test_rendered_scripts_compile_and_isolate_state(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        for p in (instance.runtime/'scripts').iterdir():
            self.assertNotIn('@@',p.read_text())
            if p.suffix=='.py':compile(p.read_text(),str(p),'exec')
            elif p.suffix=='.sh':subprocess.run(['bash','-n',str(p)],check=True)
        self.assertIn('28081',(instance.runtime/'scripts/macos-network-control.sh').read_text())
        vm=json.loads((instance.state/'instance.yaml').read_text())
        self.assertEqual(vm['mounts'][0]['location'],str(Path(self.c['shares'][0]['source']).resolve()))
        self.assertFalse(vm['propagateProxyEnv'])
        self.assertEqual(vm['osOpts']['Darwin']['suppressFirstLoginSetup'],True)
        self.assertFalse((self.home/'.lima').exists())
    def test_old_receipt_cannot_accept_new_guest(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        w.private_json(instance.receipt,{'guest':'old','fingerprint':instance.fingerprint()})
        with patch.object(instance,'identity',return_value='new'):
            with self.assertRaises(RuntimeError):instance.ready()
    def test_config_and_node_change_invalidate_receipt(self):
        instance=w.Workstation(w.load(self.p));instance.render();before=instance.fingerprint()
        self.c['shares'][0]['writable']=False;self.save()
        self.assertNotEqual(before,w.Workstation(w.load(self.p)).fingerprint())
        Path(self.c['node_file']).write_text('DIFFERENT-TEST-NODE')
        self.assertNotEqual(before,instance.fingerprint())
    def test_missing_probe_and_false_report_never_pass(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        for payload in ({},{'online':{}},{'online':{'https':False}},{'online':{'https':'true'}},{'online':{'foo':True}}):
            with patch.object(instance,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload).encode(),b'')):
                with self.assertRaises(RuntimeError):instance.network()
    def test_quarantine_falls_back_to_normal_stop(self):
        instance=w.Workstation(w.load(self.p));instance.render();w.private_json(instance.receipt,{'accepted':True})
        with patch.object(instance,'guest',side_effect=TimeoutError),patch.object(instance,'lima_cmd',return_value=subprocess.CompletedProcess([],0)) as stop:
            instance.quarantine();stop.assert_called_once_with(['stop','candidate-one'],timeout=90)
        self.assertFalse(instance.receipt.exists())
    def test_ssh_failure_is_not_a_successful_network_block(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        spec=importlib.util.spec_from_file_location('probe',instance.runtime/'scripts/macos-network-check.py');probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
        with patch.object(probe.subprocess,'run',return_value=subprocess.CompletedProcess([],255,'','SSH failed')):
            with self.assertRaises(RuntimeError):probe.guest(['curl','example.test'])
    def test_wrong_exit_and_utun_fail_independently(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        spec=importlib.util.spec_from_file_location('probe',instance.runtime/'scripts/macos-network-check.py');probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
        w.private_json(instance.state/'us-workstation-singbox.json',{'outbounds':[{'tag':'vps','server':'192.0.2.10','bind_interface':'en0'}]})
        route=subprocess.CompletedProcess([],0,' destination: 192.0.2.10\n interface: utun0\n','')
        with patch.object(probe.subprocess,'run',return_value=route):
            r=probe.host_path_checks('198.51.100.12')
        self.assertFalse(r['matches_configured_node_exit']);self.assertFalse(r['host_node_uses_dedicated_physical_route'])

    def test_failed_acceptance_invalidates_all_pending_evidence(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        for name in ('accepted.json','system-checks.json','pending-ui.json'):
            w.private_json(instance.state/name,{'passed':True})
        instance.invalidate()
        self.assertFalse(any((instance.state/name).exists() for name in ('accepted.json','system-checks.json','pending-ui.json')))
    def test_node_symlink_rejected(self):
        link=self.home/'node-link';link.symlink_to(self.c['node_file'])
        self.c['node_file']=str(link);self.save()
        with self.assertRaises(RuntimeError):w.load(self.p)

    def test_rebuild_refuses_existing_profile_without_starting(self):
        with patch.object(w.sys,'argv',['workstation','--config',str(self.p),'rebuild','--from-config',str(self.p)]), patch.object(w.Workstation,'bootstrap') as boot:
            with self.assertRaises(RuntimeError):w.main()
            boot.assert_not_called()
    def test_fault_acceptance_requires_both_faults_and_recovery(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        common={'forced_ipv4_blocked','ipv6_direct_blocked','host_socks_user_blocked','host_clash_blocked','host_dns_blocked'}
        online=dict.fromkeys(common | {'https_available','dns_available','matches_original_proxy_exit','matches_configured_node_exit','host_node_bound_to_physical_interface','host_node_uses_dedicated_physical_route'},True)
        offline=dict.fromkeys(common | {'https_blocked','dns_blocked'},True)
        full={'online':online,'guest_proxy_stopped':offline,'host_upstream_blocked':offline,'restored':online}
        with patch.object(instance,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(full).encode(),b'')):
            self.assertEqual(instance.network(True),full)
        for missing in full:
            partial={k:v for k,v in full.items() if k!=missing}
            with patch.object(instance,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(partial).encode(),b'')):
                with self.assertRaises(RuntimeError):instance.network(True)

if __name__=='__main__':unittest.main()
