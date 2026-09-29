#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline P4 background identity, clock, barrier and per-stream gate counterexamples."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import current_background_performance as c
import test_ui_background_fixture as existing
from test_ui_background_fixture import current_profile


def write(path, value):
    Path(path).write_text(json.dumps(value)); return c.reference(path)


def context_fixture(directory, variant="A", phase="DIAGNOSTIC"):
    profile = current_profile("diagnostic", 3); profile["rate_per_second"] = 20.5
    rt = {"java_home": "/synthetic/jdk", "jdk_runtime": {}, "dependencies_sha256": {}}
    resources = {"cpus": [4], "rss_limit_mib": 1536, "cell_timeout_seconds": 1000, "whole_timeout_seconds": 1000}
    admin = {"username": "root", "host": "%", "password_env": "MASSDB_UI_ADMIN_PASSWORD"}
    config = directory / "fe.conf"; config.write_text('query_port = 29030\n')
    be = directory / "be.conf"; be.write_text('be_port = 29060\n')
    refs = {"fe": c.reference(config), "be": c.reference(be)}
    values = {"environment": {"runtime_policy": {"client_cpus": [4], "jvm_heap_mib": 512}},
        "configuration": {"service_configs": refs}, "fixture": {"business_workload_sha256": c.business_binding(profile)["sha256"]},
        "client": {"runtime": rt, "resources": resources, "connection_mode": c.MODE, "admin_account": admin,
                   "read_account": profile["read_account"], "write_account": profile["write_account"]},
        "fe_artifact": "synthetic FE "+variant, "be_artifact": "synthetic BE"}
    bindings = {key:c.reference(path) for key,path in c.SOURCES.items()}
    bindings.update({key:write(directory/(key+'.json'),value) for key,value in values.items()})
    identity = {field:bindings[key]['sha256'] for key,field in c.IDENTITIES.items()}; identity['source_commit']='a'*40
    pins={role:{'pid':i,'start_ticks':10,'namespace':'net:[1]','exe':'/test/'+role,'command_sha256':'f'*64}
          for role,i in (('fe',100),('be',101))}
    context = {'schema_version':1,'window_id':'G5-test','pair_id':0,'phase':phase,'variant':variant,'group':'G5',
        'identity':identity,'bindings':bindings,'workload':write(directory/'profile.json',profile),'services':pins,
        'service_configs':refs,'target':{'name':'test','host':'127.0.0.1','query_port':29030},'admin_account':admin,
        'runtime':{'java_home':'/synthetic/jdk','jars':[]},'resources':resources,'license_scenario':'VALID',
        'coordination_seconds':30,'max_clock_uncertainty_ns':150000000,'context_deadline_monotonic_ns':time.monotonic_ns()+60*10**9,
        'host_namespace':'net:[2]'}
    return profile,context,rt


class CurrentP4PlanTest(unittest.TestCase):
    def test_actual_schedule_accepts_one_ns_but_binds_its_own_hash(self):
        value=current_profile('diagnostic',3);value['rate_per_second']=20.5
        offsets=c.plan(value)['offsets']
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'actual.tsv'
            path.write_text('sequence\toffset_ns\n'+''.join(f'{i}\t{v+(1 if i==0 else 0)}\n' for i,v in enumerate(offsets)))
            binding=c.reference(path)
            self.assertEqual(c.actual_schedule(value,binding),binding['sha256'])
            self.assertNotEqual(binding['sha256'],c.plan(value)['reference_schedule_sha256'])
            path.write_text('sequence\toffset_ns\n'+''.join(f'{i}\t{v+2}\n' for i,v in enumerate(offsets)))
            with self.assertRaisesRegex(ValueError,'seed model'):c.actual_schedule(value,c.reference(path))

    def test_total_10000_does_not_replace_10000_each_stream(self):
        value=current_profile();value['rate_per_second']=20
        with self.assertRaisesRegex(ValueError,'Each metadata/write'):c.plan(value)
        value['rate_per_second']=40
        result=c.plan(value);self.assertGreaterEqual(result['requests_per_stream'],10000)
        self.assertEqual(result['scheduled_requests'],2*result['requests_per_stream'])

    def test_three_group_formal_duration_minimums(self):
        for group,minimum in (('G5',600),('G6',600),('G7',300)):
            value=current_profile(duration=minimum);value.update(group=group,rate_per_second=80)
            self.assertEqual(c.plan(value)['warmup_seconds'],0)
            value['duration_seconds']-=1
            with self.assertRaisesRegex(ValueError,'too short'):c.plan(value)

    def test_fractional_seeded_exact_sixteen_workers(self):
        value=current_profile('diagnostic',3);value['rate_per_second']=20.5
        result=c.plan(value)
        self.assertGreaterEqual(result['requests_per_stream'],8)
        value['read_workers']=7
        with self.assertRaises(ValueError):c.plan(value)

    def test_business_excludes_rate_duration_group_but_binds_sql_oracle_account(self):
        value=current_profile('diagnostic',3);first=c.business_binding(value)
        changed=copy.deepcopy(value);changed.update(rate_per_second=2.5,duration_seconds=300,group='G7')
        self.assertEqual(first,c.business_binding(changed))
        changed['read_account']['username']='other_reader'
        self.assertNotEqual(first,c.business_binding(changed))
        changed=copy.deepcopy(value);changed['metadata_oracles'][2]['rows'][1][1]='integer'
        self.assertNotEqual(first,c.business_binding(changed))

    def test_mixed_cpu_is_not_allocated_to_streams_and_queues_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            api,profile,summary=existing.CurrentBackgroundTest().fixture(Path(temp))
            result=c.background.audit_current_receipts(api,Path(temp),profile,summary)
            self.assertAlmostEqual(result['cpu']['fe']['cpu_seconds_per_success'],1/result['successful_requests'])
            self.assertNotEqual(result['streams']['read']['queue_p99_ms'],result['streams']['write']['queue_p99_ms'])
            self.assertTrue(all('cpu' not in stream for stream in result['streams'].values()))


class ContextTest(unittest.TestCase):
    def test_runtime_accepts_real_output_package_layout_but_rejects_foreign_jar(self):
        root=c.SOURCE.parents[2]
        with tempfile.TemporaryDirectory(dir=root/'.build-records') as temp, tempfile.TemporaryDirectory(dir=root/'output') as package:
            home=Path(temp)/'jdk'
            for relative in ('bin/java','bin/javac','lib/modules','lib/server/libjvm.so','release'):
                path=home/relative;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('JAVA_VERSION="17.0.4"' if relative=='release' else 'SYNTHETIC_JDK_NO_EXECUTION')
            jars=[]
            for name in c.JARS:
                jar=Path(package)/name;jar.write_text('SYNTHETIC_JAR_NO_EXECUTION');jars.append(str(jar))
            spec={'java_home':str(home),'jars':jars}
            self.assertEqual(set(c.runtime(spec)['dependencies_sha256']),set(jars))
            with tempfile.TemporaryDirectory() as foreign:
                external=Path(foreign)/Path(jars[0]).name;external.write_text('foreign')
                spec['jars']=[str(external),*jars[1:]]
                with self.assertRaisesRegex(ValueError,'this checkout'):c.runtime(spec)

    def test_diagnostic_accepts_explicit_bound_B_without_original_A_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            profile,context,rt=context_fixture(Path(temp),'B')
            with patch.object(c,'runtime',return_value=rt),patch.object(c.api,'Guard',side_effect=AssertionError('original guard')):
                self.assertEqual(c.validate_context(context,profile),rt)

    def test_capacity_and_aa_reject_B(self):
        for phase in ('CAPACITY','AA'):
            with tempfile.TemporaryDirectory() as temp:
                profile,context,rt=context_fixture(Path(temp),'B',phase)
                with patch.object(c,'runtime',return_value=rt),self.assertRaisesRegex(ValueError,'A-only'):
                    c.validate_context(context,profile)

    def test_changed_actual_account_cannot_reuse_client_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            profile,context,rt=context_fixture(Path(temp))
            context['admin_account']['username']='other'
            with patch.object(c,'runtime',return_value=rt),self.assertRaisesRegex(ValueError,'actual runtime/resources/accounts'):
                c.validate_context(context,profile)

    def test_ab_requires_same_frozen_cell_and_prior_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);profile,context,rt=context_fixture(path,'B','AB');planned=c.plan(profile)
            cell={'group':'G5','workload_sha256':c.business_binding(profile)['sha256'],'rate':20.5,'duration_seconds':3,
                  'warmup_seconds':0,'concurrency':16,'connection_mode':c.MODE,'request_count':planned['scheduled_requests'],
                  'arrival_schedule_sha256':planned['reference_schedule_sha256']}
            schedule=path/'actual-plan.tsv';schedule.write_text('sequence\toffset_ns\n'+''.join(f'{i}\t{v}\n' for i,v in enumerate(planned['offsets'])))
            context['arrival_schedule']=c.reference(schedule)
            context['freeze']=write(path/'freeze.json',{'status':'FROZEN_ELIGIBLE','identities':{'B':context['identity']},'cell':cell})
            context['publication']=write(path/'publication.json',{'freeze':context['freeze'],'boot_id':c.statistics.boot_id(),'published_monotonic_ns':0})
            with patch.object(c,'runtime',return_value=rt):c.validate_context(context,profile)
            context['publication']=write(path/'publication.json',{'freeze':context['freeze'],'boot_id':c.statistics.boot_id(),'published_monotonic_ns':2**63})
            with patch.object(c,'runtime',return_value=rt),self.assertRaisesRegex(ValueError,'precede'):c.validate_context(context,profile)

    def test_stat_guard_detects_replacement_without_hashing_large_binary_each_poll(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'file';path.write_text('one');first=c.stamp(path)
            replacement=path.with_name('other');replacement.write_text('one');replacement.replace(path)
            self.assertNotEqual(first,c.stamp(path))


class ClockAndBarrierTest(unittest.TestCase):
    def clock_fixture(self,path):
        launch={'launch_token':'a'*64,'boot_id':c.statistics.boot_id(),'created_monotonic_ns':time.monotonic_ns(),
                'context_deadline_monotonic_ns':time.monotonic_ns()+60*10**9,'coordination_seconds':30,
                'max_clock_uncertainty_ns':150000000}
        ref=write(path/'launch.json',launch);pin={'pid':42,'start_ticks':1,'namespace':'net:[1]'}
        clock=c.Clock(path,ref,pin)
        ready={'schema_version':1,'launch_token':'a'*64,'boot_id':launch['boot_id'],'launch_sha256':ref['sha256'],
               'helper_pid':42,'helper_start_ticks':1,'namespace':'net:[1]','ready_nonce':'c'*32}
        write(path/'p4-clock-ready.json',ready)
        return clock,ready

    def test_nonce_reply_and_bounded_clock_ack(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);clock,ready=self.clock_fixture(path);clock.poll()
            self.assertIsNone(clock.bridge)
            write(path/'p4-helper-clock.json',{**ready,'nonce':clock.request['nonce'],'jvm_sample_ns':time.monotonic_ns()})
            with patch.object(c,'dependencies',return_value=[]),patch.object(c,'pin',return_value=clock.pin):clock.poll()
            self.assertIsNotNone(clock.bridge)
            self.assertEqual(c.read_json(path/'clock-ack.json')['bridge_sha256'],clock.bridge['sha256'])

    def test_wrong_nonce_or_helper_is_rejected(self):
        for mutation in ('nonce','helper_pid'):
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp);clock,ready=self.clock_fixture(path);clock.poll()
                reply={**ready,'nonce':clock.request['nonce'],'jvm_sample_ns':time.monotonic_ns()}
                reply[mutation]='b'*64 if mutation=='nonce' else 99;write(path/'p4-helper-clock.json',reply)
                with self.assertRaises(ValueError):clock.poll()

    def test_expired_context_and_excessive_uncertainty_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            clock,_=self.clock_fixture(Path(temp));clock.launch['context_deadline_monotonic_ns']=0
            with self.assertRaisesRegex(ValueError,'expired'):clock.poll()
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);clock,ready=self.clock_fixture(path);clock.poll();clock.before-=10**9
            write(path/'p4-helper-clock.json',{**ready,'nonce':clock.request['nonce'],'jvm_sample_ns':time.monotonic_ns()})
            with self.assertRaises(ValueError):clock.poll()

    def test_expired_measurement_requires_usable_post_oracle_state(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);launch=write(path/'launch.json',{'boot_id':'boot','license_scenario':'EXPIRED'})
            raw=write(path/'raw.json',{'actual':'synthetic-not-network'})
            value={'status':'VERIFIED','stage':'READY_FOR_MEASUREMENT','launch_sha256':launch['sha256'],'boot_id':'boot',
                   'raw_artifacts':[raw],'auditor':c.reference(c.SOURCE),'observed_monotonic_ns':100,'observed_license_state':'EXPIRED'}
            evidence=write(path/'barrier.json',value);c.barrier(evidence,'READY_FOR_MEASUREMENT',launch,'B')
            value['stage']='READY_FOR_VERIFICATION';evidence=write(path/'barrier.json',value)
            with self.assertRaisesRegex(ValueError,'usable'):c.barrier(evidence,'READY_FOR_VERIFICATION',launch,'B')
            for state in ('VALID','EXPIRING'):
                value['observed_license_state']=state;evidence=write(path/'barrier.json',value)
                c.barrier(evidence,'READY_FOR_VERIFICATION',launch,'B')

    def test_recovery_check_does_not_restart_or_require_failed_clock(self):
        value=c.Participant.__new__(c.Participant);value.finished=True
        value.work_pin={'pid':42};value.process=Mock();value.process.poll.return_value=None
        value.clock=Mock();value.clock.poll.side_effect=ValueError('broken prior clock')
        with patch.object(c.background.CurrentBackground,'check',return_value=[]):
            self.assertEqual(value.check(),[])
        value.clock.poll.assert_not_called()

    def test_finish_reaps_owned_child_even_if_source_or_clock_invalid(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);raw=path/'business-background';raw.mkdir()
            value=c.Window.__new__(c.Window);value.closed=False;value.output=path;value.context={'max_clock_uncertainty_ns':1}
            value.launch={'launch_token':'a','boot_id':c.statistics.boot_id()};value.launch_ref=write(path/'p4-launch.json',value.launch)
            active=Mock(output=raw,work_pin=None,clock=None);active.finish.side_effect=ValueError('oracle failed')
            active.process.poll.return_value=None;active.process.wait.return_value=2;value.active=active
            with patch.object(c.capacity,'terminate_client') as stop,patch.object(c,'dependencies',side_effect=ValueError('source drift')):
                result=value.finish(failure=ValueError('clock missing'))
            stop.assert_called_once_with(active.process);active.process.wait.assert_called_once_with(timeout=5)
            self.assertEqual(result['status'],'INVALID_WINDOW')
            self.assertIn('MissingClock',c.read_json(path/'p4-completion.json')['controller_errors'])



class NormalizeTest(unittest.TestCase):
    def fixture(self, root):
        directory=root/'window';directory.mkdir();raw=directory/'business-background';raw.mkdir()
        _,profile,summary=existing.CurrentBackgroundTest().fixture(raw)
        _,context,rt=context_fixture(root)
        context['workload']=write(root/'profile.json',profile)
        launch={**context,'launch_token':'a'*64,'boot_id':c.statistics.boot_id(),'created_monotonic_ns':1,
                'bound_runtime':rt,'actual_namespace':'net:[1]',
                'utc_anchor':{'before_monotonic_ns':1,'utc_ns':1,'after_monotonic_ns':2}}
        lr=write(directory/'p4-launch.json',launch)
        ident={'schema_version':1,'launch_token':'a'*64,'launch_sha256':lr['sha256'],'boot_id':launch['boot_id'],
               'helper_pid':42,'helper_start_ticks':99,'namespace':'net:[1]'}
        cfg=c.read_json(raw/'config.json');cfg.update(token='a'*32,p4_launch=lr,cpu_services=context['services'],target=context['target'],
                  oracle_account=context['admin_account'],namespace='net:[1]',heap_mib=512)
        write(raw/'config.json',cfg)
        for name in ('window-start.json','window-end.json','measurement-start.json','measurement-end.json'):
            value=c.read_json(raw/name);value.update(ident)
            if name=='measurement-start.json':value['java_monotonic_ns']=999999980
            if name=='measurement-end.json':value['java_monotonic_ns']=4000000020
            write(raw/name,value)
        base={'token':'a'*32,'pid':42,'start_ticks':99,**ident}
        for name,ns in (('ready.json',999990000),('verification-ready.json',4000000030),('verification-start.json',4000001000)):
            write(raw/name,{**base,'java_monotonic_ns':ns})
        summary.update(ident,automatic_write_replays=0,workers_closed=True,cleanup_confirmed=True,cleanup_end_java_ns=4000002000)
        model={'rows':1000000,'full_values_verified':True,'canonical_sha256':c.background.expected_source_digest()}
        summary.update(source_before=model,source_after=model)
        count=summary['planned_write_batches']
        resolution=[{'sequence':i,'rows':100,'request_state':'ACK','observed_committed':True,'unknown_absence_is_rollback_proof':False} for i in range(count)]
        write(raw/'write-batch-resolution.json',resolution)
        summary['target_after']={'rows':count*100,'full_values_verified':True,'exact_id_domains_verified':True,
            'canonical_sha256':c.background.expected_rows_digest(range(1000000000,1000000000+count*100))}
        write(raw/'summary.json',summary)
        requests=c.background.audit_current_receipts(c.api,raw,profile,summary)
        models=c.background.audit_full_models(c.api,raw,profile,summary)
        write(raw/'controller.json',{'status':'PASS','cleanup_confirmed':True,'owned_child_exited':True,'errors':[],
                                    'receipt_audit':requests,'full_model_audit':models})
        for role in ('read','write'):
            settings={'enable_sql_cache':'false','enable_query_cache':'false','enable_short_circuit_query':'true',
                      'query_timeout':str(profile['timeout_seconds']),'insert_timeout':str(profile['timeout_seconds'])}
            if role=='write':settings.update(group_commit='off_mode',enable_insert_strict='true',enable_unique_key_partial_update='false')
            for worker in range(8):
                write(raw/f'{role}-{worker}-session.json',settings)
                cid=worker+(1 if role=='read' else 9)
                write(raw/f'{role}-{worker}-p4-open.json',{**base,'role':role,'worker':worker,'connections_opened':1,
                    'connection_class':'org.mariadb.jdbc.Connection','driver_version':'3.0.9','connection_id':cid})
                write(raw/f'{role}-{worker}-p4-end.json',{**base,'role':role,'worker':worker,'connection_id':cid,
                    'same_client_and_connection':True,'operations':(count+7-worker)//8})
        write(directory/'frozen.json',c.freeze_inputs(launch,profile,rt))
        classes=raw/'classes';classes.mkdir();(classes/'LicenseUiBackground.class').write_bytes(b'SYNTHETIC_CLASS_NO_EXECUTION')
        write(raw/'helper-identity.json',{'dependencies':{},'frozen':c.read_json(directory/'frozen.json'),'classes':{str(classes/'LicenseUiBackground.class'):c.api.sha(classes/'LicenseUiBackground.class')}})
        command=['/synthetic/jdk/bin/java','-Xmx512m','-cp',str(classes),'LicenseUiBackground',str(raw/'config.json')]
        import hashlib
        sha=hashlib.sha256(b'\0'.join(os.fsencode(x) for x in command)+b'\0').hexdigest()
        actual={'pin':{'pid':42,'start_ticks':99,'command_sha256':sha,'namespace':'net:[1]','exe':'/synthetic/jdk/bin/java'},
                'expected_launch':{'command_sha256':sha}}
        actualref=write(raw/'background-process.json',actual)
        waitref=write(raw/'process-lifecycle.json',[{'pid':42,'parent_wait_complete':True,'exit_code':0}])
        helper=write(raw/'p4-helper-clock.json',{**ident,'nonce':'n'*64,'jvm_sample_ns':100000000})
        bridge=write(raw/'p4-clock-bridge.json',{**ident,'nonce':'n'*64,'controller_before_ns':99999999,'controller_after_ns':100000001,'helper_clock':helper})
        write(raw/'p4-clock-ready.json',{**ident,'ready_nonce':'r'*32})
        request={**ident,'nonce':'n'*64,'ready_nonce':'r'*32}
        write(raw/'clock-request.json',request)
        write(raw/'clock-ack.json',{**request,'helper_clock_sha256':helper['sha256'],'bridge_sha256':bridge['sha256']})
        completion={**ident,'exit_code':0,'parent_wait_complete':True,'remaining_live_pids':[],'controller_errors':[],
                    'bridge':bridge,'actual_launch':actualref,'actual_wait_events':waitref,'completed_monotonic_ns':4000002010,
                    'utc_anchor':{'before_monotonic_ns':4000002001,'utc_ns':1,'after_monotonic_ns':4000002002}}
        complete=write(directory/'p4-completion.json',completion)
        for name,stage,seen,before in (('release','READY_FOR_MEASUREMENT',999990100,999990200),
                                      ('verification','READY_FOR_VERIFICATION',4000000100,4000000200)):
            rawproof=write(root/(name+'-proof.json'),{'synthetic':True})
            proof=write(root/(name+'-state.json'),{'status':'VERIFIED','stage':stage,'launch_sha256':lr['sha256'],
                'boot_id':launch['boot_id'],'raw_artifacts':[rawproof],'auditor':c.reference(c.SOURCE),'observed_monotonic_ns':seen,
                'observed_license_state':'ORIGINAL_A_NO_LICENSE'})
            write(directory/(name+'-barrier.json'),{'evidence':proof,'before_monotonic_ns':before})
            write(raw/('release.json' if name=='release' else 'verify-release.json'),{'token':'a'*32,'controller_monotonic_ns':before+1})
        write(directory/'ready-observation.json',{'observed_monotonic_ns':999990050})
        write(directory/'quiescence-observation.json',{'observed_monotonic_ns':4000000050})
        return {'window_directory':str(directory),'launch':lr,'completion':complete},rt

    def test_full_synthetic_raw_normalization_and_mixed_cpu(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest,rt=self.fixture(Path(temp))
            with patch.object(c,'validate_context',return_value=rt):result=c.normalize(manifest)
            self.assertEqual(result['status'],'DIAGNOSTIC_VERIFIED_NOT_QUALIFIED')
            self.assertEqual(result['window']['metrics']['fe_cpu_seconds_per_success'],1/result['window']['successful_requests'])
            self.assertFalse(result['group_event_or_ui_qualification'])
            self.assertEqual(result['window']['warmup_seconds'],0)

    def test_normalize_rejects_wait_reuse_full_model_and_barrier_mutations(self):
        for mutation in ('wait','reuse','full_target','barrier','extra_class','nonce'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);manifest,rt=self.fixture(root);raw=root/'window/business-background'
                if mutation=='wait':
                    path=root/'window/p4-completion.json';value=c.read_json(path);value['parent_wait_complete']=False
                    manifest['completion']=write(path,value)
                elif mutation=='reuse':
                    path=raw/'read-0-p4-end.json';value=c.read_json(path);value['same_client_and_connection']=False;write(path,value)
                elif mutation=='full_target':
                    path=raw/'summary.json';value=c.read_json(path);value['target_after']['canonical_sha256']='0'*64;write(path,value)
                elif mutation=='barrier':
                    path=root/'window/verification-barrier.json';value=c.read_json(path);value['before_monotonic_ns']=0;write(path,value)
                elif mutation=='nonce':
                    path=raw/'clock-request.json';value=c.read_json(path);value['nonce']='x'*64;write(path,value)
                else:(raw/'classes/Injected.class').write_bytes(b'UNBOUND')
                with patch.object(c,'validate_context',return_value=rt),self.assertRaises(ValueError):c.normalize(manifest)



class InstalledSlotsTest(unittest.TestCase):
    def test_symlinked_lib_slots_accept_and_wrong_actual_config_pid_or_jar_reject(self):
        root=c.SOURCE.parents[2]
        with tempfile.TemporaryDirectory(dir=root/'.build-records') as temp:
            base=Path(temp);install=base/'installation';package=base/'package';home=base/'jdk';(home/'bin').mkdir(parents=True)
            (home/'bin/java').write_text('JAVA_SYNTHETIC')
            context={'services':{},'service_configs':{},'bindings':{},'runtime':{'java_home':str(home)}}
            environments={};commands={}
            for role,pid in (('fe',12345),('be',12346)):
                (install/role/'conf').mkdir(parents=True);(install/role/'bin').mkdir();(package/role/'lib').mkdir(parents=True)
                (install/role/'lib').symlink_to(package/role/'lib',target_is_directory=True)
                config=install/role/'conf'/(role+'.conf');config.write_text('query_port=29030\n')
                artifact=package/role/'lib'/('doris-fe.jar' if role=='fe' else 'doris_be');artifact.write_text(role)
                (install/role/'bin'/(role+'.pid')).write_text(str(pid))
                context['service_configs'][role]=c.reference(config);context['bindings'][role+'_artifact']=c.reference(artifact)
                context['services'][role]={'pid':pid,'exe':str((home/'bin/java') if role=='fe' else artifact)}
                environments[f'/proc/{pid}/environ']=('DORIS_HOME='+str(install/role)+'\0').encode()
            loaded=install/'fe/lib/doris-fe.jar'
            environments['/proc/12345/environ']+=('CLASSPATH='+str(loaded)+'\0UNRELATED_SECRET=DO_NOT_ARCHIVE\0').encode()
            commands['/proc/12345/cmdline']=b'java\0org.apache.doris.DorisFE\0'
            original=Path.read_bytes
            def read(path):return environments.get(str(path),commands.get(str(path))) if str(path) in environments or str(path) in commands else original(path)
            with patch.object(Path,'read_bytes',read):
                observed=c.installed_slots(context)
                self.assertNotIn('UNRELATED_SECRET',json.dumps(observed))
                self.assertEqual(observed['installation']['fe'],str(install/'fe'))
                wrong=base/'wrong/fe/conf/fe.conf';wrong.parent.mkdir(parents=True);wrong.write_text('query_port=29030\n')
                original_config=context['service_configs']['fe'];context['service_configs']['fe']=c.reference(wrong)
                with self.assertRaisesRegex(ValueError,'DORIS_HOME'):c.installed_slots(context)
                context['service_configs']['fe']=original_config
                (install/'be/bin/be.pid').write_text('999')
                with self.assertRaisesRegex(ValueError,'PID'):c.installed_slots(context)
                (install/'be/bin/be.pid').write_text('12346')
                other=base/'other/doris-fe.jar';other.parent.mkdir();other.write_text('fe')
                commands['/proc/12345/cmdline']=('java\0-cp\0'+str(other)+'\0org.apache.doris.DorisFE\0').encode()
                with self.assertRaisesRegex(ValueError,'loaded JAR'):c.installed_slots(context)

    def test_formal_requires_prebound_actual_java_schedule(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);_,context,rt=context_fixture(root,phase='AA')
            value=current_profile('formal',600);value['rate_per_second']=40
            context['workload']=write(root/'profile.json',value)
            context['bindings']['fixture']=write(root/'fixture.json',{'business_workload_sha256':c.business_binding(value)['sha256']})
            context['identity']['fixture_sha256']=context['bindings']['fixture']['sha256']
            # Enlarge the predeclared total bound, including full prepare/verify phases.
            context['resources']['cell_timeout_seconds']=context['resources']['whole_timeout_seconds']=2000
            client=c.read_json(context['bindings']['client']['path']);client['resources']=context['resources']
            context['bindings']['client']=write(root/'client.json',client);context['identity']['client_sha256']=context['bindings']['client']['sha256']
            with patch.object(c,'runtime',return_value=rt),self.assertRaisesRegex(ValueError,'actual Java plan-only'):
                c.validate_context(context,value)


if __name__ == '__main__':unittest.main(verbosity=2)
