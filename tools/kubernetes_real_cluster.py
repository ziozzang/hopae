#!/usr/bin/env python3
"""Real API qualification, restricted to our named private kind cluster.

Creates only uniquely named fixture namespaces/RBAC and removes them afterwards.
Never prints credentials or kubeconfig. Does not change production Hopae settings.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import yaml

p=argparse.ArgumentParser();p.add_argument('--driver',required=True,type=Path);p.add_argument('--state-dir',required=True,type=Path);args=p.parse_args()
os.umask(0o077)
container='zerotrust-qualification-control-plane'
state=args.state_dir.resolve();assert state.is_dir()
kubeconfig=state/'kubeconfig';assert kubeconfig.is_file()
configuration=yaml.safe_load(kubeconfig.read_text());assert configuration['current-context']=='kind-zerotrust-qualification'
cluster=configuration['clusters'][0]['cluster'];origin=cluster['server'];assert origin.startswith('https://127.0.0.1:')
run_dir=state/('tokenreview-'+str(int(time.time()))+'-'+secrets.token_hex(3));run_dir.mkdir(mode=0o700)
(run_dir/'ca.pem').write_bytes(base64.b64decode(cluster['certificate-authority-data']))
name='zt-qual-'+secrets.token_hex(4);role=name+'-reviewer';driver=args.driver.resolve()
def kubectl(*argv, document=None):
    r=subprocess.run(['docker','exec',*(['-i']if document is not None else []),container,'kubectl','--kubeconfig','/etc/kubernetes/admin.conf',*argv],input=None if document is None else json.dumps(document),capture_output=True,text=True,timeout=30)
    if r.returncode:raise RuntimeError('owned kubectl operation failed; details suppressed')
    return r.stdout

def apply(value):kubectl('apply','-f','-',document=value)
def token(account, bound=False, audience=None):
    argv=['create','token',account,'-n',name,'--duration=10m']
    if bound:argv+=['--bound-object-kind=Pod','--bound-object-name=worker']
    if audience:argv+=['--audience='+audience]
    return kubectl(*argv).strip()
def invoke(value, changes=None, reviewer=None):
    cfg=dict(config,**(changes or {}));(run_dir/'config.json').write_text(json.dumps(cfg));(run_dir/'reviewer').write_text(reviewer or reviewer_token)
    r=subprocess.run([str(driver),str(run_dir/'config.json'),str(run_dir/'ca.pem'),str(run_dir/'reviewer')],input=json.dumps({'token':value,'now_ms':int(time.time()*1000)}),text=True,capture_output=True,timeout=10)
    if r.returncode:raise RuntimeError('native TokenReview driver failed; details suppressed')
    assert value not in r.stdout+r.stderr and reviewer_token not in r.stdout+r.stderr
    return json.loads(r.stdout)
def pod():return {'apiVersion':'v1','kind':'Pod','metadata':{'namespace':name,'name':'worker'},'spec':{'serviceAccountName':'worker','terminationGracePeriodSeconds':0,'containers':[{'name':'pause','image':'registry.k8s.io/pause:3.10','imagePullPolicy':'IfNotPresent','resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'cpu':'50m','memory':'32Mi'}}}]}}
created=False
try:
    apply({'apiVersion':'v1','kind':'Namespace','metadata':{'name':name}});created=True
    for account in ['worker','reviewer']:apply({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'namespace':name,'name':account}})
    apply({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'name':role},'rules':[{'apiGroups':['authentication.k8s.io'],'resources':['tokenreviews'],'verbs':['create']}]})
    apply({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRoleBinding','metadata':{'name':role},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':role},'subjects':[{'kind':'ServiceAccount','name':'reviewer','namespace':name}]})
    apply({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'namespace':name,'name':'reviewer-objects'},'rules':[{'apiGroups':[''],'resources':['pods','serviceaccounts'],'verbs':['get'],'resourceNames':['worker']}]})
    apply({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'namespace':name,'name':'reviewer-objects'},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'reviewer-objects'},'subjects':[{'kind':'ServiceAccount','namespace':name,'name':'reviewer'}]})
    apply(pod())
    issuer=json.loads(kubectl('get','--raw','/.well-known/openid-configuration'))['issuer']
    reviewer_token=token('reviewer');credential=token('worker',True,'workload.example.test')
    config={'api_origin':origin,'issuer':issuer,'cluster_id':'owned-kind-qualification','audience':'workload.example.test','namespaces':[name],'timeout_ms':1000}
    first=invoke(credential);assert first['status']=='verified' and first['kind']=='Workload'
    assert invoke(credential,changes={'cluster_id':'different-cluster'})['subject']!=first['subject']
    signature=credential.split('.')[-1];raw=bytearray(base64.urlsafe_b64decode(signature+'='*((4-len(signature)%4)%4)));raw[0]^=1
    altered='.'.join(credential.split('.')[:2])+'.'+base64.urlsafe_b64encode(raw).decode().rstrip('=')
    assert invoke(altered)['status']=='invalid'
    assert invoke(credential,changes={'issuer':'https://different-issuer.example.test'})['status']=='invalid'
    assert invoke(credential,changes={'audience':'different-audience'})['status']=='invalid'
    assert invoke(token('worker',False,'workload.example.test'))['status']=='invalid'
    assert invoke(credential,reviewer=token('worker'))['status']=='unavailable'
    deletion_started=time.monotonic();kubectl('delete','pod','worker','-n',name,'--grace-period=0','--force','--wait=true')
    deadline=time.monotonic()+70
    while invoke(credential)['status']!='invalid':
        if time.monotonic()>=deadline:raise RuntimeError('real Pod-bound credential was not revoked within fixture deadline')
        time.sleep(.25)
    withdrawal_ms=int((time.monotonic()-deletion_started)*1000)
    apply(pod());replacement=token('worker',True,'workload.example.test');second=invoke(replacement);assert second['status']=='verified' and second['subject']!=first['subject'] and invoke(credential)['status']=='invalid'
    kubectl('delete','serviceaccount','worker','-n',name,'--wait=true')
    deadline=time.monotonic()+70
    while invoke(replacement)['status']!='invalid':
        if time.monotonic()>=deadline:raise RuntimeError('real ServiceAccount credential was not revoked within fixture deadline')
        time.sleep(.25)
    version=json.loads(kubectl('version','-o','json'))['serverVersion']['gitVersion']
    report={'cluster_version':version,'real_signature_tamper_denial':True,'issuer_audience_refusal':True,'unbound_refusal':True,'reviewer_minimum_rbac':True,'pod_delete_withdrawal_ms':withdrawal_ms,'pod_recreation_changes_identity':True,'serviceaccount_delete_withdrawal':True,'native_workload_kind':True,'production_changed':False}
    (run_dir/'report.json').write_text(json.dumps(report,indent=2)+'\n');(state/'tokenreview-latest.json').write_text(json.dumps({'report':str(run_dir/'report.json')})+'\n')
    success='PASS: real Kubernetes '+version+' TokenReview/live metadata: signature tamper/issuer/audience/unbound denial, minimum reviewer RBAC, Pod/ServiceAccount deletion, recreated Pod identity; Pod withdrawal '+str(withdrawal_ms)+'ms; production unchanged'
finally:
    (run_dir/'reviewer').unlink(missing_ok=True)
    cleanup_failed=False
    if created:
        for argv in [('delete','clusterrolebinding',role,'--ignore-not-found'),('delete','clusterrole',role,'--ignore-not-found'),('delete','namespace',name,'--ignore-not-found','--wait=false')]:
            try:kubectl(*argv)
            except Exception:cleanup_failed=True

    if cleanup_failed:raise RuntimeError("owned fixture cleanup failed")
print(success)
