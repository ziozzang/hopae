#!/usr/bin/env python3
"""Owned OpenLDAP TLS credential fixture. Never uses an operational directory."""
import argparse,os,secrets,socket,ssl,subprocess,tempfile,time,threading
from pathlib import Path

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',default='hopae/owned-openldap:bookworm');args=parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='owned-hopae-ldap-')as temporary:
        root=Path(temporary);(root/'db').mkdir();name='owned-hopae-ldap-'+secrets.token_hex(6)
        with socket.socket()as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        with socket.socket()as sock:sock.bind(('127.0.0.1',0));starttls_port=sock.getsockname()[1]
        def openssl(*arguments):subprocess.run(['openssl',*arguments],cwd=root,check=True,capture_output=True)
        for ca in ['ca','wrong-ca']:openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',ca+'.key','-out',ca+'.pem','-days','1','-subj','/CN=Owned '+ca,'-addext','basicConstraints=critical,CA:TRUE')
        openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=Owned LDAP')
        (root/'server.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
        openssl('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','server.ext','-out','server.pem')
        bind,user=secrets.token_hex(32),secrets.token_hex(32)
        (root/'slapd.conf').write_text('include /etc/ldap/schema/core.schema\ninclude /etc/ldap/schema/cosine.schema\ninclude /etc/ldap/schema/inetorgperson.schema\npidfile /owned/slapd.pid\nargsfile /owned/slapd.args\nmodulepath /usr/lib/ldap\nmoduleload back_mdb\nTLSCACertificateFile /owned/ca.pem\nTLSCertificateFile /owned/server.pem\nTLSCertificateKeyFile /owned/server.key\ndatabase mdb\nmaxsize 16777216\nsuffix "dc=example,dc=test"\nrootdn "cn=reader,dc=example,dc=test"\nrootpw '+bind+'\ndirectory /owned/db\naccess to * by dn.exact="cn=reader,dc=example,dc=test" manage by self read by anonymous auth\n')
        ldif='dn: dc=example,dc=test\nobjectClass: dcObject\nobjectClass: organization\ndc: example\no: Owned fixture\n\ndn: uid=alice,dc=example,dc=test\nobjectClass: inetOrgPerson\nuid: alice\ncn: Alice\nsn: Owned\njpegPhoto:: AAH/\nuserPassword: '+user+'\n'
        for label in ['One','Two']:
            ldif+='\ndn: cn=Duplicate'+label+',dc=example,dc=test\nobjectClass: inetOrgPerson\nuid: duplicated\ncn: Duplicate'+label+'\nsn: Owned\nuserPassword: '+user+'\n'
        subprocess.run(['docker','run','--rm','-i','-v',str(root)+':/owned',args.image,'slapadd','-f','/owned/slapd.conf'],input=ldif.encode(),check=True,capture_output=True)
        try:
            subprocess.run(['docker','run','-d','--rm','--network','host','--name',name,'-v',str(root)+':/owned',args.image,'slapd','-f','/owned/slapd.conf','-h',f'ldaps://127.0.0.1:{port} ldap://127.0.0.1:{starttls_port}','-d','0'],check=True,capture_output=True)
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('owned directory readiness deadline')
            env=dict(os.environ,OWNED_LDAP_ENDPOINT=f'ldaps://127.0.0.1:{port}',OWNED_LDAP_CA=str(root/'ca.pem'),OWNED_LDAP_WRONG_CA=str(root/'wrong-ca.pem'),OWNED_LDAP_BIND_KEY=bind,OWNED_LDAP_USER_PASSWORD=user)
            for endpoint,mode in [(f'ldaps://127.0.0.1:{port}','0'),(f'ldap://127.0.0.1:{starttls_port}','1')]:
                env.update(OWNED_LDAP_ENDPOINT=endpoint,OWNED_LDAP_STARTTLS=mode)
                peers=[];failures=[]
                deep=b'\x04\x00'
                for _ in range(64):deep=b'\x30\x82'+len(deep).to_bytes(2,'big')+deep
                for key,packet in [('OWNED_LDAP_OVERSIZE',b'\x30\x83\x01\x00\x00'),('OWNED_LDAP_DEEP',deep),('OWNED_LDAP_EMPTY',b'\x30\x00'),('OWNED_LDAP_RESULT',b'\x30\x08\x02\x01\x01\x61\x03\x0a\x01\x00'),('OWNED_LDAP_CONTROL',bytes.fromhex('301702010161070a010004000400a00930070403312e320100')),('OWNED_LDAP_WRONG_BIND',bytes.fromhex('3009020101640404003000')),('OWNED_LDAP_WRONG_SEARCH',None),('OWNED_LDAP_WRONG_RESULT',bytes.fromhex('300c02010178070a010004000400')),('OWNED_LDAP_FLOOD',b'flood')]:
                    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(60)
                    env[key]=f'ldaps://127.0.0.1:{listener.getsockname()[1]}'
                    def serve(listener=listener,packet=packet):
                        try:
                            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'server.pem',root/'server.key')
                            connection,_=listener.accept()
                            with context.wrap_socket(connection,server_side=True)as tls:
                                tls.settimeout(1);assert tls.recv(8192)
                                if packet is None or packet==b'flood':
                                    tls.sendall(bytes.fromhex('300c02010161070a010004000400'));assert tls.recv(8192)
                                    tls.sendall(bytes.fromhex('300c02010261070a010004000400')if packet is None else bytes.fromhex('3009020102640404003000')*9)
                                else:tls.sendall(packet)
                                # Keep the peer open: require client rejection rather than server EOF.
                                while tls.recv(8192):pass
                        except Exception as error:failures.append(type(error).__name__)
                        finally:listener.close()
                    thread=threading.Thread(target=serve,daemon=True);thread.start();peers.append(thread)

                result=subprocess.run(['cargo','test','--locked','--lib','owned_ldaps_authenticates_immutable_identity_and_rejects_bad_credentials_and_ca','--','--ignored'],env=env,capture_output=True)
                for peer in peers:peer.join(timeout=2)
                if failures or any(peer.is_alive() for peer in peers):raise RuntimeError('malicious LDAP TLS peer was not rejected promptly: '+','.join(failures))
                if result.returncode:
                    diagnostic=(result.stdout+result.stderr).decode(errors='replace').replace(bind,'[REDACTED]').replace(user,'[REDACTED]')
                    Path('/tmp/hopae-owned-ldap-test-failure.log').write_text(diagnostic)
                    raise RuntimeError('owned LDAP credential test failed; sanitized diagnostic in /tmp/hopae-owned-ldap-test-failure.log')
            print('PASS: real owned OpenLDAP over LDAPS and mandatory StartTLS; stable immutable identity, repeated independent user binds, invalid/missing/duplicate/injected credentials, wrong CA rejection, oversized/deep/semantic-malformed and wrong-operation TLS response rejection and backend-circuit classification. Portal/session/runtime activation is not qualified.')
        finally:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if __name__=='__main__':main()
