#!/usr/bin/env python3
"""Owned OpenLDAP TLS credential fixture. Never uses an operational directory."""
import argparse,os,secrets,socket,subprocess,tempfile,time
from pathlib import Path

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',default='hopae/owned-openldap:bookworm');args=parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='owned-hopae-ldap-')as temporary:
        root=Path(temporary);(root/'db').mkdir();name='owned-hopae-ldap-'+secrets.token_hex(6)
        with socket.socket()as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        def openssl(*arguments):subprocess.run(['openssl',*arguments],cwd=root,check=True,capture_output=True)
        for ca in ['ca','wrong-ca']:openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',ca+'.key','-out',ca+'.pem','-days','1','-subj','/CN=Owned '+ca,'-addext','basicConstraints=critical,CA:TRUE')
        openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=Owned LDAP')
        (root/'server.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
        openssl('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','server.ext','-out','server.pem')
        bind,user=secrets.token_hex(32),secrets.token_hex(32)
        (root/'slapd.conf').write_text('include /etc/ldap/schema/core.schema\ninclude /etc/ldap/schema/cosine.schema\ninclude /etc/ldap/schema/inetorgperson.schema\npidfile /owned/slapd.pid\nargsfile /owned/slapd.args\nmodulepath /usr/lib/ldap\nmoduleload back_mdb\nTLSCACertificateFile /owned/ca.pem\nTLSCertificateFile /owned/server.pem\nTLSCertificateKeyFile /owned/server.key\ndatabase mdb\nmaxsize 16777216\nsuffix "dc=example,dc=test"\nrootdn "cn=reader,dc=example,dc=test"\nrootpw '+bind+'\ndirectory /owned/db\naccess to * by dn.exact="cn=reader,dc=example,dc=test" manage by self read by anonymous auth\n')
        ldif='dn: dc=example,dc=test\nobjectClass: dcObject\nobjectClass: organization\ndc: example\no: Owned fixture\n\ndn: uid=alice,dc=example,dc=test\nobjectClass: inetOrgPerson\nuid: alice\ncn: Alice\nsn: Owned\nuserPassword: '+user+'\n'
        for label in ['One','Two']:
            ldif+='\ndn: cn=Duplicate'+label+',dc=example,dc=test\nobjectClass: inetOrgPerson\nuid: duplicated\ncn: Duplicate'+label+'\nsn: Owned\nuserPassword: '+user+'\n'
        subprocess.run(['docker','run','--rm','-i','-v',str(root)+':/owned',args.image,'slapadd','-f','/owned/slapd.conf'],input=ldif.encode(),check=True,capture_output=True)
        try:
            subprocess.run(['docker','run','-d','--rm','--network','host','--name',name,'-v',str(root)+':/owned',args.image,'slapd','-f','/owned/slapd.conf','-h',f'ldaps://127.0.0.1:{port}','-d','0'],check=True,capture_output=True)
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('owned directory readiness deadline')
            env=dict(os.environ,OWNED_LDAP_ENDPOINT=f'ldaps://127.0.0.1:{port}',OWNED_LDAP_CA=str(root/'ca.pem'),OWNED_LDAP_WRONG_CA=str(root/'wrong-ca.pem'),OWNED_LDAP_BIND_KEY=bind,OWNED_LDAP_USER_PASSWORD=user)
            result=subprocess.run(['cargo','test','--locked','--lib','owned_ldaps_authenticates_immutable_identity_and_rejects_bad_credentials_and_ca','--','--ignored'],env=env,capture_output=True)
            if result.returncode:
                diagnostic=(result.stdout+result.stderr).decode(errors='replace').replace(bind,'[REDACTED]').replace(user,'[REDACTED]')
                Path('/tmp/hopae-owned-ldap-test-failure.log').write_text(diagnostic)
                raise RuntimeError('owned LDAP credential test failed; sanitized diagnostic in /tmp/hopae-owned-ldap-test-failure.log')
            print('PASS: real owned OpenLDAP over verified TLS; stable immutable identity, repeated independent user binds, invalid/missing/duplicate/injected credentials, wrong CA rejection and backend-circuit classification. Portal/session/runtime activation is not qualified.')
        finally:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if __name__=='__main__':main()
