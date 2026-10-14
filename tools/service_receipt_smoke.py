#!/usr/bin/env python3
"""Owned actual Hopae executable + Hangang receipt client; no operating data."""
import argparse, base64, copy, hashlib, hmac, http.client, json, os
from pathlib import Path
import secrets, selectors, socket, subprocess, tempfile, time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--live-validation', action='store_true', help='client supports cached receipt revocation and outage checks')
    args = parser.parse_args()
    os.umask(0o077)
    def port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='owned-service-receipt-') as directory:
        root = Path(directory)
        def openssl(*argv):
            return subprocess.check_output(['openssl', *map(str, argv)], stderr=subprocess.DEVNULL)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=owned-ca','-keyout',root/'ca.key','-out',root/'ca.pem','-addext','basicConstraints=critical,CA:TRUE')
        for name, usage in [('server','serverAuth'),('client','clientAuth')]:
            openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=owned','-keyout',root/(name+'.key'),'-out',root/(name+'.csr'))
            extension=root/(name+'.ext');extension.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:hopae.example.test\n')
            openssl('x509','-req','-in',root/(name+'.csr'),'-CA',root/'ca.pem','-CAkey',root/'ca.key','-CAcreateserial','-days','1','-extfile',extension,'-out',root/(name+'.pem'))
        openssl('genpkey','-algorithm','ED25519','-out',root/'issuer.pem')
        seed=openssl('pkey','-in',root/'issuer.pem','-outform','DER')
        public=openssl('pkey','-in',root/'issuer.pem','-pubout','-outform','DER')
        assert len(seed)==48 and len(public)==44
        env=dict(os.environ,OWNED_RECEIPT_SEED=base64.b64encode(seed[-32:]).decode(),OWNED_RECEIPT_CALLER=secrets.token_hex(24),OWNED_RECEIPT_CREDENTIAL=secrets.token_hex(24),OWNED_RECEIPT_DELEGATION=secrets.token_hex(24))
        portal,gateway,grpc,admin=[port() for _ in range(4)]
        profile={'authority_id':'owned','profiles':[{'service_id':'orders','host':'orders.example.test','ports':[443],'realm':'owned','api_keys':[{'token_env':'OWNED_RECEIPT_CREDENTIAL','subject':'worker'}],'networks':['203.0.113.0/24']}]}
        pin=base64.b64encode(public[-32:]).decode()
        config={'state_dir':str(root/'state'),'listen':{'portal':f'127.0.0.1:{portal}','gateway':f'127.0.0.1:{gateway}','grpc_gateway':f'127.0.0.1:{grpc}','admin':f'127.0.0.1:{admin}','native_gateway_tls':{'certificate':str(root/'server.pem'),'key':str(root/'server.key'),'client_ca':str(root/'ca.pem')}},'portal':{'public_url':'https://auth.example.test'},'gateway':{'kind':'hangang','caller_key_env':'OWNED_RECEIPT_CALLER'},'apps':[{'app_id':'orders','hosts':['orders.example.test']}],'admin':{'public_url':'https://admin.example.test','hangang_delegation':{'authority':'hangang','key_env':'OWNED_RECEIPT_DELEGATION'}},'authentication_gateway':profile,'receipt_issuer':{'issuer_ref':'owned','key_epoch':1,'identity_authority_epoch':'epoch1','public_key':pin,'seed_env':'OWNED_RECEIPT_SEED','scopes':[{'service':'orders','audience':'orders-api'}]}}
        server_config=root/'server.json';server_config.write_text(json.dumps(config))
        client_config={'settings':{'transport':'grpc','address':f'localhost:{grpc}','tls':{'server_name':'hopae.example.test','ca':str(root/'ca.pem'),'certificate':str(root/'client.pem'),'key':str(root/'client.key')}},'issuer_ref':'owned','key_epoch':1,'public_key':pin,'service':'orders','audience':'orders-api','method':'GET','target':'/private','body':'','headers':[['x-hopae-contract','1'],['x-forwarded-host','orders.example.test'],['x-forwarded-proto','https'],['x-forwarded-port','443'],['x-forwarded-for','203.0.113.9'],['x-original-method','GET'],['x-original-url','https://orders.example.test/private']]}
        client_path=root/'client.json';client_path.write_text(json.dumps(client_config))
        def publish(revision, configuration):
            path='/v1/authentication/profiles/publish';body=json.dumps({'revision':revision,'configuration':configuration},separators=(',',':')).encode()
            actor={'authority':'hangang','actor_id':0,'actor_name':'system','timestamp':int(time.time()),'nonce':secrets.token_hex(16),'method':'POST','path':path,'body_sha256':hashlib.sha256(body).hexdigest(),'handle_sha256':hashlib.sha256(b'').hexdigest(),'client_ip':'127.0.0.1','user_agent':None}
            raw=json.dumps(actor,separators=(',',':')).encode()
            encode=lambda value:base64.urlsafe_b64encode(value).decode().rstrip('=')
            headers={'Host':'admin.example.test','Content-Type':'application/json','x-hopae-delegation':encode(raw),'x-hopae-delegation-mac':encode(hmac.digest(env['OWNED_RECEIPT_DELEGATION'].encode(),raw,'sha256')),'x-forwarded-host':'admin.example.test','x-forwarded-proto':'https','x-forwarded-port':'443','x-forwarded-for':'127.0.0.1'}
            connection=http.client.HTTPConnection('127.0.0.1',admin,timeout=3)
            try:
                connection.request('POST',path,body=body,headers=headers);response=connection.getresponse();result=json.loads(response.read())
                assert response.status==200, 'owned profile publication refused'
                return result['revision']
            finally:connection.close()
        processes=[]
        with (root/'server.log').open('wb') as server_log, (root/'client.log').open('wb') as client_log:
            try:
                server=subprocess.Popen([str(args.server.resolve()),'run','--config',str(server_config)],env=env,stdout=server_log,stderr=server_log);processes.append(server)
                for _ in range(100):
                    assert server.poll() is None, 'owned server exited before readiness'
                    connection=http.client.HTTPConnection('127.0.0.1',portal,timeout=.5)
                    try:
                        connection.request('GET','/healthz');response=connection.getresponse();response.read()
                        if response.status==200:break
                    except OSError:pass
                    finally:connection.close()
                    time.sleep(.05)
                else:raise RuntimeError('owned receipt server readiness deadline')
                client=subprocess.Popen([str(args.client.resolve()),str(client_path)],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=client_log,text=True);processes.append(client)
                selector=selectors.DefaultSelector();selector.register(client.stdout,selectors.EVENT_READ)
                def command(value):
                    client.stdin.write(value+'\n');client.stdin.flush()
                    assert selector.select(5), 'owned client reply deadline'
                    line=client.stdout.readline();assert line, 'owned client refused expected result'
                    return json.loads(line)
                allowed=command('allow');assert allowed['allowed'] is True and allowed['revision']==1
                revision=publish(1,None);assert revision==2
                assert command('deny')['allowed'] is False
                revision=publish(revision,copy.deepcopy(profile));assert revision==3
                restored=command('allow');assert restored['allowed'] is True and restored['revision']==revision
                if not args.live_validation:
                    client.stdin.close();assert client.wait(timeout=3)==0
                    selector.close()
                openssl('genpkey','-algorithm','ED25519','-out',root/'wrong-issuer.pem')
                wrong_public=openssl('pkey','-in',root/'wrong-issuer.pem','-pubout','-outform','DER')[-32:]
                for name in ['caller', 'issuer', 'audience', 'service', 'server-name', 'key', 'key-epoch']:
                    denied_config=copy.deepcopy(client_config);denied_env=dict(env)
                    if name=='caller':denied_env['OWNED_RECEIPT_CALLER']=secrets.token_hex(24)
                    elif name=='issuer':denied_config['issuer_ref']='untrusted-issuer'
                    elif name=='audience':denied_config['audience']='untrusted-api'
                    elif name=='service':denied_config['service']='billing'
                    elif name=='key':denied_config['public_key']=base64.b64encode(wrong_public).decode()
                    elif name=='key-epoch':denied_config['key_epoch']=2
                    else:denied_config['settings']['tls']['server_name']='wrong.example.test'
                    denied_path=root/(name+'.json');denied_path.write_text(json.dumps(denied_config))
                    result=subprocess.run([str(args.client.resolve()),str(denied_path)],input='deny\n',env=denied_env,text=True,stdout=subprocess.PIPE,stderr=client_log,timeout=5)
                    assert result.returncode==0 and json.loads(result.stdout)['allowed'] is False, 'unsafe receipt accepted: '+name
                if args.live_validation:
                    fresh=command('allow');assert fresh['allowed'] is True and fresh['revision']==revision
                    server.kill();server.wait(timeout=3)
                    assert command('outage')['allowed'] is False
                    client.stdin.close();assert client.wait(timeout=3)==0
                    selector.close()
                    print('PASS: actual Hopae executable and Pumgye mTLS live client; cached unexpired receipt revocation, restoration, authority outage and seven trust refusals')
                else:
                    print('PASS: actual Hopae executable with configured mTLS receipt client; pinned request-bound receipt, signed profile CAS, same-channel revocation/restoration and caller/issuer/service/audience/server-name/key/epoch refusal')
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=8)
                        except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':main()
