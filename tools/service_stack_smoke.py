#!/usr/bin/env python3
"""Owned actual Hangang/Hopae/Pumgye, optional Sumunjang; no operational identities."""
import argparse, copy, hashlib, sqlite3, http.client, http.server, json, os, secrets, ssl, struct, subprocess, tempfile, threading, time, urllib.request
from pathlib import Path
from remote_hangang_smoke import port

def main():
    p=argparse.ArgumentParser()
    for name in ['gateway','hopae','pumgye']:p.add_argument('--'+name+'-binary',required=True,type=Path)
    p.add_argument('--sumunjang-binary',type=Path)
    p.add_argument('--grpc',action='store_true')
    p.add_argument('--resource-catalog',action='store_true')
    p.add_argument('--external-verifier',action='store_true')
    p.add_argument('--durable-restart',action='store_true')
    args=p.parse_args()
    if args.resource_catalog and not args.grpc:p.error('--resource-catalog requires --grpc')
    processes=[];seen=[];verifier_state={'unavailable':False,'calls':0}
    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(dict(self.headers));self.send_response(200);self.end_headers();self.wfile.write(b'owned')
        do_POST=do_GET
        def log_message(self,*args):pass
    class Verifier(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            verifier_state['calls']+=1
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if verifier_state['unavailable']:status,reply=503,{}
            elif self.headers.get('Authorization')!='Bearer '+api_key:status,reply=401,{}
            elif body.get('service_id')!='orders':status,reply=200,{'active':False}
            else:status,reply=200,{'active':True,'subject':'worker','service_id':'orders','expires_at':int(time.time()*1000)+1000}
            self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(reply).encode())
        def log_message(self,*args):pass
    verifier=http.server.ThreadingHTTPServer(('127.0.0.1',0),Verifier);threading.Thread(target=verifier.serve_forever,daemon=True).start()
    origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin);threading.Thread(target=origin.serve_forever,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='owned-service-stack-') as tmp:
            root=Path(tmp);public,admin,portal,http_verify,hop_native,pum_http,pum_native=[port() for _ in range(7)]
            hop_grpc,pum_grpc,guard_http,guard_native,guard_grpc=[port() for _ in range(5)]
            api_key,caller,system,pum_decision,pum_admin,guard_collector,guard_admin=[secrets.token_hex(32) for _ in range(7)]
            env=dict(os.environ,OWNED_API_KEY=api_key,HOPAE_TEST_GATEWAY_KEY=caller,FIXTURE_KEY=caller,HANGANG_ADMIN_TOKEN=system,PUMGYE_DECISION_TOKEN=pum_decision,PUMGYE_ADMIN_TOKEN=pum_admin,HANGANG_GUARD_COLLECTOR_TOKEN=guard_collector,HANGANG_GUARD_ADMIN_TOKEN=guard_admin)
            def openssl(*a):subprocess.run(['openssl',*a],cwd=root,check=True,capture_output=True)
            openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Owned CA','-addext','basicConstraints=critical,CA:TRUE')
            for name,usage in [('server','serverAuth'),('client','clientAuth')]:
                openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name)
                (root/(name+'.ext')).write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:hopae.example.test,DNS:pumgye.example.test,DNS:sumunjang.example.test,IP:127.0.0.1\n')
                openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile',name+'.ext','-out',name+'.pem')
            digest=hashlib.sha256(bytes([1]))
            for value in ['owned-external' if args.external_verifier else 'hopae:owned','services','worker']:
                value=value.encode();digest.update(struct.pack('!Q',len(value)));digest.update(value)
            subject='s_'+digest.hexdigest()[:48]
            policy={'version':1,'information_classes':['internal','restricted'],'services':{'orders':{'permissions':['read','write'],'require_guard':bool(args.sumunjang_binary),'roles':{'reader':{'permissions':['read'],'information_classes':['internal'],'minimum_aal':0}},'users':{subject:['reader']},'networks':[{'cidr':'127.0.0.1/32','roles':['reader']}]}}}
            policy['services']['billing']=copy.deepcopy(policy['services']['orders'])
            if args.resource_catalog:policy['resources']={'db:orders':{'service':'orders','information_class':'internal','actions':{'select':'read','update':'write'},'minimum_aal':0}}
            (root/'policy.json').write_text(json.dumps({'revision':0,'policy':policy}))
            hop=json.loads((Path(__file__).resolve().parent.parent/'tests/fixtures/m1-basic.json').read_text());hop['providers']=[];hop['state_dir']=str(root/'hopae-state')
            hop['listen']={'portal':f'127.0.0.1:{portal}','gateway':f'127.0.0.1:{http_verify}','native_gateway':f'0.0.0.0:{hop_native}','native_gateway_tls':{'certificate':str(root/'server.pem'),'key':str(root/'server.key'),'client_ca':str(root/'ca.pem')}}
            if args.grpc:hop['listen']['grpc_gateway']=f'0.0.0.0:{hop_grpc}'
            hop['apps'][0]['app_id']='orders';hop['apps'][0]['ports']=[public]
            hop['authentication_gateway']={'authority_id':'owned','profiles':[{'service_id':'orders','host':'app.example.test','ports':[public],'realm':'services','api_keys':[{'token_env':'OWNED_API_KEY','subject':'worker'}],'networks':['127.0.0.1/32']}]}
            if args.external_verifier:
                profile=hop['authentication_gateway']['profiles'][0];profile.pop('api_keys');profile['api_relay']={'url':f'http://127.0.0.1:{verifier.server_port}/verify','issuer':'owned-external','allow_private_endpoints':True,'timeout_ms':500}
            (root/'hopae.json').write_text(json.dumps(hop))
            def tls(name):return {'server_name':name,'ca':str(root/'ca.pem'),'certificate':str(root/'client.pem'),'key':str(root/'client.key')}
            config={'http':[{'id':'orders','host':'app.example.test','path_prefix':'/secure','path_match':'segment_prefix','access_mode':'protected','backends':[f'http://127.0.0.1:{origin.server_port}'],'auth':{'url':f'http://127.0.0.1:{http_verify}/_hopae/verify','native':{'address':f'127.0.0.1:{hop_native}','tls':tls('hopae.example.test')},'request_headers':['authorization'],'response_headers':['x-forwarded-user','x-hopae-aal','x-hopae-principal-kind'],'static_request_headers':{'x-hopae-gateway-key':{'env':'FIXTURE_KEY'},'x-hopae-contract':'1'},'forward_response':True},'resource_policy':{'resource_id':'orders','principal':{'source':'external','subject_header':'x-forwarded-user'},'allow':[],'pumgye':{'service_id':'orders','information_class':'internal','permissions':{'GET':['read'],'POST':['write']}}}}],'pumgye_authority':{'decision_address':f'127.0.0.1:{pum_native}','management_address':f'127.0.0.1:{pum_http}','decision_token_env':'PUMGYE_DECISION_TOKEN','admin_token_env':'PUMGYE_ADMIN_TOKEN','tls':tls('pumgye.example.test'),'timeout_ms':1000}}
            if args.grpc:
                config['http'][0]['auth']['native'].update(transport='grpc',address=f'localhost:{hop_grpc}')
                config['pumgye_authority'].update(transport='grpc',decision_address=f'localhost:{pum_grpc}')
            if args.resource_catalog:
                resource=config['http'][0]['resource_policy'];resource.pop('pumgye');resource['pumgye_resource']={'service_id':'orders','resource':'db:orders','actions':{'GET':'select','POST':'update'}}
            (root/'hangang.json').write_text(json.dumps(config))
            def start(binary,argv,name):
                log=open(root/(name+'.log'),'ab');process=subprocess.Popen([str(binary.resolve()),*argv],env=env,stdout=log,stderr=log);processes.append(process);return process
            def wait(url,process,name,context=None,token=None):
                for _ in range(150):
                    if process.poll() is not None:raise RuntimeError(name+' startup failed')
                    try:
                        with urllib.request.urlopen(urllib.request.Request(url,headers={'Authorization':'Bearer '+token} if token else {}),context=context,timeout=1) as response:
                            if response.status==200:return
                    except OSError:time.sleep(.05)
                raise RuntimeError(name+' readiness deadline')
            context=ssl.create_default_context(cafile=str(root/'ca.pem'));context.load_cert_chain(str(root/'client.pem'),str(root/'client.key'))
            pum_args=['--listen',f'0.0.0.0:{pum_http}','--decision-listen',f'0.0.0.0:{pum_native}','--database',str(root/'pumgye.db'),'--policy',str(root/'policy.json'),'--tls-cert',str(root/'server.pem'),'--tls-key',str(root/'server.key'),'--client-ca',str(root/'ca.pem'),*(['--grpc-listen',f'0.0.0.0:{pum_grpc}'] if args.grpc else [])]
            owner=start(args.pumgye_binary,pum_args,'pumgye');wait(f'https://127.0.0.1:{pum_http}/healthz',owner,'pumgye',context)
            hopae=start(args.hopae_binary,['run','--config',str(root/'hopae.json')],'hopae');wait(f'http://127.0.0.1:{portal}/healthz',hopae,'hopae')
            guard_args=[]
            if args.sumunjang_binary:
                sum_args=['--listen',f'127.0.0.1:{guard_http}','--decision-listen',f'0.0.0.0:{guard_native}','--database',str(root/'sumunjang.db'),'--decision-tls-cert',str(root/'server.pem'),'--decision-tls-key',str(root/'server.key'),'--decision-client-ca',str(root/'ca.pem')]
                if args.grpc:sum_args+=['--grpc-listen',f'0.0.0.0:{guard_grpc}']
                sumunjang=start(args.sumunjang_binary,sum_args,'sumunjang')
                wait(f'http://127.0.0.1:{guard_http}/healthz',sumunjang,'sumunjang')
                def guard_api(path,method,body):
                    req=urllib.request.Request(f'http://127.0.0.1:{guard_http}'+path,headers={'Authorization':'Bearer '+guard_admin,'Content-Type':'application/json'},data=json.dumps(body).encode(),method=method)
                    with urllib.request.urlopen(req,timeout=2) as response:return response.status
                assert guard_api('/v1/policy','PUT',{'mode':'enforce','allow':[]})==200
                guard_args=['--guard-url',f'http://127.0.0.1:{guard_http}','--guard-decision-tcp',f'localhost:{guard_grpc if args.grpc else guard_native}','--guard-decision-server-name','sumunjang.example.test','--guard-decision-ca',str(root/'ca.pem'),'--guard-decision-cert',str(root/'client.pem'),'--guard-decision-key',str(root/'client.key'),'--guard-timeout-ms','1000']
                if args.grpc:guard_args+=['--guard-decision-grpc']
            gateway=start(args.gateway_binary,['--config',str(root/'hangang.json'),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{admin}','--tls-cert',str(root/'server.pem'),'--tls-key',str(root/'server.key'),'--threads','2','--lua-workers','1','--drain-seconds','1',*guard_args],'hangang');wait(f'http://127.0.0.1:{admin}/v1/config',gateway,'hangang',token=system)
            def request(method='GET',key=api_key):
                c=http.client.HTTPSConnection('127.0.0.1',public,context=ssl.create_default_context(cafile=str(root/'ca.pem')),timeout=3)
                headers={'Host':'app.example.test','x-forwarded-user':'u_forged','x-hopae-aal':'3'}
                if key is not None:headers['Authorization']='Bearer '+key
                before=len(seen)
                c.request(method,'/secure',headers=headers);r=c.getresponse();status=r.status;r.read();c.close()
                assert len(seen)==before+(1 if status==200 else 0),'refused request reached application upstream'
                return status
            def api(path='/v1/config',method='GET',document=None,extra=None):
                headers={'Authorization':'Bearer '+system,'Content-Type':'application/json'}
                if extra:headers.update(extra)
                with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{admin}'+path,data=None if document is None else json.dumps(document).encode(),headers=headers,method=method),timeout=3) as r:return json.loads(r.read()),dict(r.headers)
            assert request()==200 and request()==200
            assert len(seen)==2 and all(not any(k.lower()=='authorization' for k in h) for h in seen)
            assert all(h.get('x-forwarded-user')==subject and h.get('x-hopae-aal')=='0' for h in seen)
            assert request('POST')==403 and request(key=None)==401 and request(key='invalid-service-key-at-least-thirty-two-bytes')==401
            root_config,_=api();current,headers=api('/v1/pumgye/policy');original=copy.deepcopy(current);current['policy']['services']['orders']['users']={}
            updated,_=api('/v1/pumgye/policy','PUT',current,{'If-Match':f'"{current["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']});assert request()==403
            original['revision']=updated['revision'];restored,_=api('/v1/pumgye/policy','PUT',original,{'If-Match':f'"{updated["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']});assert restored['revision']>updated['revision'] and request()==200
            for mode in ['network','assurance']:
                denied=copy.deepcopy(restored)
                if mode=='network':denied['policy']['services']['orders']['networks']=[]
                else:denied['policy']['services']['orders']['roles']['reader']['minimum_aal']=1
                denied,_=api('/v1/pumgye/policy','PUT',denied,{'If-Match':f'"{denied["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']})
                assert request()==403,mode+' did not deny service identity'
                baseline=copy.deepcopy(original);baseline['revision']=denied['revision']
                restored,_=api('/v1/pumgye/policy','PUT',baseline,{'If-Match':f'"{denied["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']})
            now,_=api();assert now['revision']==root_config['revision'],'Pumgye publication rewrote gateway configuration'
            if args.resource_catalog:
                classified,headers=api('/v1/pumgye/policy')
                classified['policy']['resources']['db:orders']['information_class']='restricted'
                classified,_=api('/v1/pumgye/policy','PUT',classified,{'If-Match':f'"{classified["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']});assert request()==403,'owner class clearance was ignored'
                classified['policy']['resources']['db:orders']['information_class']='internal'
                classified,_=api('/v1/pumgye/policy','PUT',classified,{'If-Match':f'"{classified["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']});assert request()==200
                catalog=copy.deepcopy(classified['policy']['resources'])
                classified['policy']['resources']={}
                classified,_=api('/v1/pumgye/policy','PUT',classified,{'If-Match':f'"{classified["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']});assert request()==403,'catalog deletion did not refuse'
                classified['policy']['resources']=catalog
                classified,_=api('/v1/pumgye/policy','PUT',classified,{'If-Match':f'"{classified["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']});assert request()==200
            else:
                classified=copy.deepcopy(now);classified['http'][0]['resource_policy']['pumgye']['information_class']='restricted'
                classified,_=api('/v1/config','PUT',classified,{'If-Match':f'"{classified["revision"]}"'});assert request()==403,'class clearance was ignored'
                classified['http'][0]['resource_policy']['pumgye']['information_class']='internal';api('/v1/config','PUT',classified,{'If-Match':f'"{classified["revision"]}"'})
            gate_name='pumgye_resource' if args.resource_catalog else 'pumgye'
            changed,_=api();changed['http'][0]['resource_policy'][gate_name]['service_id']='billing';changed,_=api('/v1/config','PUT',changed,{'If-Match':f'"{changed["revision"]}"'});assert request()==403,'API credential crossed service audience'
            changed['http'][0]['resource_policy'][gate_name]['service_id']='orders';api('/v1/config','PUT',changed,{'If-Match':f'"{changed["revision"]}"'});assert request()==200
            if args.external_verifier:
                verifier_state['unavailable']=True
                for _ in range(3):assert request()==503
                calls=verifier_state['calls'];assert request()==503 and verifier_state['calls']==calls,'open connector circuit sent another request'
                print('PASS: actual external authentication API outage opens the circuit and suppresses additional calls.')
            if args.sumunjang_binary:
                # Network revocation must prevent the protected upstream call.
                count=len(seen)
                assert guard_api('/v1/blocks','POST',{'network':'127.0.0.1/32','expires_at':int(time.time())+600,'reason':'owned fixture'})==200
                assert request()==403 and len(seen)==count
                assert guard_api('/v1/blocks','DELETE',{'network':'127.0.0.1/32'})==200
                if not args.external_verifier:assert request()==200
                count=len(seen);sumunjang.terminate();sumunjang.wait(timeout=5)
                assert request()==503 and len(seen)==count
                sumunjang=start(args.sumunjang_binary,sum_args,'sumunjang-restarted')
                wait(f'http://127.0.0.1:{guard_http}/healthz',sumunjang,'sumunjang-restarted')
                if not args.external_verifier:
                    for _ in range(20):
                        if request()==200:break
                        time.sleep(.1)
                    else:raise AssertionError('network authority reconnect deadline')
            if not args.external_verifier:
                persisted,headers=api('/v1/pumgye/policy')
                persisted['policy']['services']['orders']['users']={}
                api('/v1/pumgye/policy','PUT',persisted,{'If-Match':f'"{persisted["revision"]}"','x-hangang-config-revision':headers['x-hangang-config-revision']})
                assert request()==403
            count=len(seen);owner.terminate();assert owner.wait(timeout=8)==0;assert request()==503 and len(seen)==count
            if not args.external_verifier:
                owner=start(args.pumgye_binary,pum_args,'pumgye-restarted')
                wait(f'https://127.0.0.1:{pum_http}/healthz',owner,'pumgye-restarted',context)
                for _ in range(20):
                    status=request()
                    assert status in (403,503),'restarted permission authority resurrected bootstrap grant'
                    if status==403:break
                    time.sleep(.1)
                else:raise AssertionError('permission authority reconnect deadline')
                print('PASS: durable permission revocation survives actual Pumgye restart and unchanged bootstrap grants.')
            if args.durable_restart:
                hopae.terminate();hopae.wait(timeout=5)
                # Owned offline operator fixture: install a tombstone while keeping bootstrap unchanged.
                with sqlite3.connect(root/'hopae-state'/'hopae.db') as db:
                    key='authentication_profile_authority_v1'
                    raw=db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone();assert raw,'startup did not import the authority'
                    document=json.loads(raw[0]);document['revision']+=1;document['configuration']=None;document['digest']=hashlib.sha256(b'null').hexdigest()
                    db.execute('UPDATE meta SET value=? WHERE key=?',(json.dumps(document),key))
                hopae=start(args.hopae_binary,['run','--config',str(root/'hopae.json')],'hopae-restarted');wait(f'http://127.0.0.1:{portal}/healthz',hopae,'hopae-restarted')
                status=request();assert status in (401,503),f'restarted authority returned {status}'
                # The first borrowed connection can be stale after process replacement; it must fail closed.
                for _ in range(3):assert request()==401,'reconnected authority resurrected the disabled profile'
                print('PASS: owned offline tombstone survives actual Hopae restart despite unchanged bootstrap file.')
            label='four' if args.sumunjang_binary else 'three'
            transport='gRPC' if args.grpc else ('HOP1/PPG1/HGD1' if args.sumunjang_binary else 'HOP1/PPG1')
            print(f'PASS: {label} actual processes over mTLS {transport}; scoped API authentication, service/IP/class/method rights, guest denial, durable revocation/restoration, audience isolation, credential consumption and authority-outage fail-closed. Network authority included when configured; no full-stack throughput claim.')
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        origin.shutdown();origin.server_close();verifier.shutdown();verifier.server_close()

if __name__=='__main__':main()
