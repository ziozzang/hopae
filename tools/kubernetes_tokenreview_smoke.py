#!/usr/bin/env python3
"""Owned HTTPS TokenReview mock; tests transport/attestation, not real Kubernetes signatures."""
import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading

parser=argparse.ArgumentParser();parser.add_argument('--driver',required=True,type=Path);args=parser.parse_args();driver=args.driver.resolve()
with tempfile.TemporaryDirectory(prefix='hopae-tokenreview-owned-') as directory:
    root=Path(directory)
    def run(*argv):subprocess.run(argv,check=True,capture_output=True)
    def ca(name):
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN='+name,'-keyout',str(root/(name+'.key')),'-out',str(root/(name+'.pem')),'-addext','basicConstraints=critical,CA:TRUE')
    ca('ca');ca('other-ca')
    run('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(root/'server.key'),'-out',str(root/'server.csr'))
    (root/'server.ext').write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
    run('openssl','x509','-req','-in',str(root/'server.csr'),'-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(root/'server.ext'),'-out',str(root/'server.pem'))
    reviewer=secrets.token_urlsafe(32);(root/'reviewer').write_text(reviewer);(root/'reviewer').chmod(0o600)
    def encode(v):return base64.urlsafe_b64encode(json.dumps(v,separators=(',',':')).encode()).decode().rstrip('=')
    token=encode({'alg':'RS256'})+'.'+encode({'iss':'https://issuer.example.test','sub':'system:serviceaccount:blue:worker','aud':['workload.example.test'],'exp':10,'kubernetes.io':{'namespace':'blue','serviceaccount':{'name':'worker','uid':'sa-1'},'pod':{'name':'worker-pod','uid':'pod-1'}}})+'.'+base64.urlsafe_b64encode(b'owned-fixture-not-a-real-jwt-signature').decode().rstrip('=')
    state={'mode':'valid','calls':0,'redirects':0}
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            assert self.headers.get('Authorization')=='Bearer '+reviewer
            expected={'/api/v1/namespaces/blue/serviceaccounts/worker':('worker','sa-1'),'/api/v1/namespaces/blue/pods/worker-pod':('worker-pod','pod-1')}
            if self.path not in expected:self.send_response(404);self.end_headers();return
            name,uid=expected[self.path]
            if state['mode']=='object-unavailable':self.send_response(503);self.end_headers();return
            if state['mode']=='deleted-pod' and '/pods/' in self.path:self.send_response(404);self.end_headers();return
            if state['mode']=='recreated-pod' and '/pods/' in self.path:uid='replacement-pod'
            metadata={'name':name,'namespace':'blue','uid':uid}
            if state['mode']=='deleting-sa' and '/serviceaccounts/' in self.path:metadata['deletionTimestamp']='2026-10-14T00:00:00Z'
            if state['mode']=='object-oversize':metadata['padding']='x'*16385
            body=json.dumps({'apiVersion':'meta.k8s.io/v1','kind':'PartialObjectMetadata','metadata':metadata}).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def do_POST(self):
            if self.path=='/stolen':state['redirects']+=1
            assert self.path=='/apis/authentication.k8s.io/v1/tokenreviews'
            state['calls']+=1
            assert self.headers.get('Authorization')=='Bearer '+reviewer
            assert self.headers.get('Authorization')!='Bearer '+token
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert body['apiVersion']=='authentication.k8s.io/v1' and body['kind']=='TokenReview' and body['spec']['token']==token and body['spec']['audiences']==['workload.example.test']
            mode=state['mode']
            if mode=='redirect':self.send_response(302);self.send_header('Location','https://127.0.0.1:'+str(self.server.server_port)+'/stolen');self.end_headers();return
            if mode=='reviewer-denied':self.send_response(403);self.end_headers();return
            reply={'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','spec':{'token':token},'status':{'authenticated':True,'audiences':['workload.example.test'],'user':{'username':'system:serviceaccount:blue:worker','uid':'sa-1','extra':{'authentication.kubernetes.io/pod-name':['worker-pod'],'authentication.kubernetes.io/pod-uid':['pod-1']}}}}
            if mode=='denied':reply['status']={'user':{},'error':'invalid fixture credential'}
            if mode=='uid':reply['status']['user']['uid']='sa-2'
            if mode=='pod':reply['status']['user']['extra']['authentication.kubernetes.io/pod-uid']=['other-pod']
            if mode=='audience':reply['status']['audiences']=['other']
            if mode=='username':reply['status']['user']['username']='system:serviceaccount:red:worker'
            if mode=='missing-bound':reply['status']['user']['extra']={}
            if mode=='oversize':reply['padding']='x'*65537
            data=json.dumps(reply).encode();self.send_response(201);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
            try:self.wfile.write(data)
            except (OSError,ssl.SSLError):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'server.pem',root/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True);threading.Thread(target=server.serve_forever,daemon=True).start()
    config={'api_origin':'https://127.0.0.1:'+str(server.server_port),'issuer':'https://issuer.example.test','cluster_id':'example-cluster','audience':'workload.example.test','namespaces':['blue'],'timeout_ms':1000}
    def invoke(attempts=1,ca_file='ca.pem',changes=None):
        current=dict(config,**(changes or {}));(root/'config.json').write_text(json.dumps(current))
        env=dict(os.environ,HTTPS_PROXY='http://127.0.0.1:1',ALL_PROXY='http://127.0.0.1:1')
        r=subprocess.run([str(driver),str(root/'config.json'),str(root/ca_file),str(root/'reviewer')],input=json.dumps({'token':token,'now_ms':100,'attempts':attempts}),text=True,capture_output=True,env=env,timeout=10)
        assert r.returncode==0,'native fixture driver failed';assert token not in r.stdout+r.stderr and reviewer not in r.stdout+r.stderr,'credential output'
        return [json.loads(line) for line in r.stdout.splitlines()]
    try:
        first=invoke()[0];assert first['status']=='verified' and first['kind']=='Workload' and first['service']=='orders'
        other=invoke(changes={'cluster_id':'other-cluster'})[0];assert other['subject']!=first['subject']
        state['mode']='denied';before=state['calls'];assert all(v['status']=='invalid' for v in invoke(attempts=5));assert state['calls']-before==5
        for mode in ['uid','pod','audience','username','missing-bound']:
            state['mode']=mode;before=state['calls'];assert all(v['status']=='unavailable' for v in invoke(attempts=5));assert state['calls']-before==3
        for mode in ['deleted-pod','recreated-pod','deleting-sa']:
            state['mode']=mode;before=state['calls'];assert all(v['status']=='invalid' for v in invoke(attempts=5));assert state['calls']-before==5
        for mode in ['reviewer-denied','redirect','oversize','object-unavailable','object-oversize']:
            state['mode']=mode;before=state['calls'];assert all(v['status']=='unavailable' for v in invoke(attempts=5));assert state['calls']-before==3
        assert state['redirects']==0
        state['mode']='valid';before=state['calls'];assert invoke(ca_file='other-ca.pem')[0]['status']=='unavailable' and state['calls']==before
        before=state['calls'];assert invoke(changes={'namespaces':['red']})[0]['status']=='invalid' and state['calls']==before
        before=state['calls'];assert invoke(changes={'issuer':'https://other-issuer.example.test'})[0]['status']=='invalid' and state['calls']==before
        print('PASS: owned TLS TokenReview, reviewer/client credential isolation, exact service-account/Pod/audience binding, workload namespace separation, bounded bodies, redirect/proxy/CA refusal, source circuit opening, no credential output; mock does not qualify real cluster JWT signatures')
    finally:server.shutdown();server.server_close()
