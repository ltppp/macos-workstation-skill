import copy
from contextlib import ExitStack
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
        self.tmp=tempfile.TemporaryDirectory(dir="/tmp");self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.patch=patch.object(Path,'home',return_value=self.home);self.patch.start();self.addCleanup(self.patch.stop)
        share=self.home/'project';share.mkdir()
        self.c={'profile':'test-a','guest_user':'worker','limactl':str(self.home/'limactl'), 'limactl_sha256':'a'*64,
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
            instance.quarantine();stop.assert_called_once_with(['stop','test-a'],timeout=90)
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

    def test_long_socket_path_rejected_before_bootstrap(self):
        self.c['profile']='long-profile-'+'x'*25;self.save()
        with self.assertRaisesRegex(RuntimeError,'socket path too long'):w.Workstation(w.load(self.p))

    def test_clipboard_stages_guest_helper_before_read(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        events=[]
        class Bridge:
            def call(self, guest, action, **kwargs):
                events.append(('read' if action=='read' else 'write',guest))
                if action=='read':raise RuntimeError('intentional endpoint stop')
        with patch.object(instance,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')), patch.object(instance,'checked_guest',side_effect=lambda *a,**k:events.append(('stage',True))), patch('importlib.util.module_from_spec',return_value=Bridge()), patch('importlib.machinery.SourceFileLoader.exec_module'):
            with self.assertRaisesRegex(RuntimeError,'intentional endpoint stop'):instance.clipboard()
        self.assertEqual(events[0],('stage',True))

    def creation_fixture(self, phase):
        instance=w.Workstation(w.load(self.p));instance.render()
        record={'fingerprint':instance.fingerprint(),'phase':phase}
        w.private_json(instance.state/'creation.json',record)
        return instance

    def test_resume_staging_never_creates_or_deletes_disk(self):
        instance=self.creation_fixture('created')
        vm=instance.lima/self.c['profile'];vm.mkdir(parents=True)
        disk=vm/'disk';disk.write_bytes(b'preserved')
        with ExitStack() as stack:
            for method in ('creation_preflight','render','proxy'):
                stack.enter_context(patch.object(instance,method))
            commands=stack.enter_context(patch.object(instance,'lima_cmd',return_value=subprocess.CompletedProcess([],0)))
            stack.enter_context(patch.object(instance,'script',return_value=b'stage=ready'))
            instance.bootstrap()
        self.assertEqual(commands.call_args_list[0].args[0],['start','--tty=false','test-a'])
        self.assertEqual(commands.call_count,1)
        self.assertEqual(disk.read_bytes(),b'preserved')
        self.assertEqual(json.loads((instance.state/'creation.json').read_text())['phase'],'staged')

    def test_interrupted_create_does_not_adopt_partial_disk(self):
        instance=self.creation_fixture('creating');(instance.lima/self.c['profile']).mkdir(parents=True)
        with patch.object(instance,'lima_cmd') as command:
            with self.assertRaisesRegex(RuntimeError,'interrupted'):instance.bootstrap()
            command.assert_not_called()

    def test_creation_change_cannot_resume(self):
        instance=self.creation_fixture('created')
        Path(self.c['node_file']).write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'changed'):instance.creation_record()

    def test_bootstrap_staging_failure_stops_only_candidate_and_keeps_disk(self):
        instance=self.creation_fixture('created');vm=instance.lima/self.c['profile'];vm.mkdir(parents=True)
        with ExitStack() as stack:
            for method in ('creation_preflight','render','proxy'):
                stack.enter_context(patch.object(instance,method))
            commands=stack.enter_context(patch.object(instance,'lima_cmd',return_value=subprocess.CompletedProcess([],0)))
            stack.enter_context(patch.object(instance,'script',side_effect=RuntimeError('staging failed')))
            with self.assertRaisesRegex(RuntimeError,'staging failed'):instance.bootstrap()
        self.assertEqual([c.args[0] for c in commands.call_args_list],
                         [['start','--tty=false','test-a'],['stop','test-a']])
        self.assertTrue(vm.is_dir())
        self.assertEqual(json.loads((instance.state/'creation.json').read_text())['phase'],'created')

    def test_creation_preflight_refuses_low_disk_before_any_state(self):
        instance=w.Workstation(w.load(self.p));Path(self.c['ipsw']).write_bytes(b'image')
        with patch.object(instance,'prerequisites'),patch.object(w.shutil,'disk_usage',return_value=type('Usage',(),{'free':1})()):
            with self.assertRaisesRegex(RuntimeError,'disk space'):instance.creation_preflight({'phase':'prepared'})
        self.assertFalse(instance.state.exists())

    def test_creation_preflight_refuses_occupied_port(self):
        instance=w.Workstation(w.load(self.p));Path(self.c['ipsw']).write_bytes(b'image')
        with patch.object(instance,'prerequisites'),patch.object(w.shutil,'disk_usage',return_value=type('Usage',(),{'free':100*1024**3})()),patch.object(w.socket,'socket') as sock:
            sock.return_value.__enter__.return_value.bind.side_effect=OSError('busy')
            with self.assertRaisesRegex(RuntimeError,'occupied'):instance.creation_preflight({'phase':'prepared'})
        self.assertFalse(instance.state.exists())

    def test_missing_desktop_retains_system_evidence(self):
        instance=w.Workstation(w.load(self.p));instance.render()
        evidence={'guest':'same','fingerprint':instance.fingerprint(),'time':w.time.time()}
        w.private_json(instance.state/'system-checks.json',evidence)
        with patch.object(instance,'identity',return_value='same'),patch.object(instance,'checked_guest',return_value=b'root'),patch.object(instance,'network') as network:
            with self.assertRaises(w.PreparationRequired):instance.finish()
            network.assert_not_called()
        self.assertEqual(json.loads((instance.state/'system-checks.json').read_text()),evidence)

    def test_main_preparation_failure_does_not_quarantine(self):
        instance=self.creation_fixture('staged');(instance.lima/self.c['profile']).mkdir(parents=True)
        with patch.object(w.sys,'argv',['workstation','--config',str(self.p),'finish-acceptance']),patch.object(w.Workstation,'prerequisites'),patch.object(w.Workstation,'finish',side_effect=w.PreparationRequired('login')),patch.object(w.Workstation,'quarantine') as quarantine:
            with self.assertRaises(w.PreparationRequired):w.main()
            quarantine.assert_not_called()

    def test_fresh_create_failure_retains_partial_disk_and_stops(self):
        instance=w.Workstation(w.load(self.p));vm=instance.lima/self.c['profile']
        def command(args, **kwargs):
            if args[0]=='create':
                vm.mkdir(parents=True);(vm/'disk').write_bytes(b'partial')
                return subprocess.CompletedProcess(args,1,b'',b'creation failed')
            return subprocess.CompletedProcess(args,0,b'',b'')
        with patch.object(instance,'creation_preflight'),patch.object(instance,'proxy'),patch.object(instance,'lima_cmd',side_effect=command) as calls:
            with self.assertRaisesRegex(RuntimeError,'create failed'):instance.bootstrap()
        self.assertEqual([c.args[0][0] for c in calls.call_args_list],['create','stop'])
        self.assertEqual((vm/'disk').read_bytes(),b'partial')
        self.assertEqual(json.loads((instance.state/'creation.json').read_text())['phase'],'creating')

    def test_bootstrap_refuses_accepted_instance_without_mutation(self):
        instance=self.creation_fixture('staged');w.private_json(instance.receipt,{'accepted':'existing'})
        with patch.object(instance,'lima_cmd') as command:
            with self.assertRaisesRegex(RuntimeError,'Already accepted'):instance.bootstrap()
            command.assert_not_called()
        self.assertEqual(json.loads(instance.receipt.read_text()),{'accepted':'existing'})

if __name__=='__main__':unittest.main()
