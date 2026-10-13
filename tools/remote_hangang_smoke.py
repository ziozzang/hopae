#!/usr/bin/env python3
"""Owned real Hangang/Hopae mTLS processes; anonymous identity and outage checks."""
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gateway-binary', required=True, type=Path)
    parser.add_argument('--hopae-binary', required=True, type=Path)
    args = parser.parse_args()
    processes = []
    hits = []
    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
        def log_message(self, *args):
            pass
    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='owned-hopae-mtls-') as directory:
            root = Path(directory)
            def openssl(*args):
                subprocess.run(['openssl', *args], cwd=root, check=True, capture_output=True)
            openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=Owned CA', '-addext', 'basicConstraints=critical,CA:TRUE')
            for name, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
                openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', name+'.key', '-out', name+'.csr', '-subj', '/CN='+name)
                (root/(name+'.ext')).write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:hopae.example.test,DNS:app.example.test,IP:127.0.0.1\n')
                openssl('x509', '-req', '-in', name+'.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', name+'.ext', '-out', name+'.pem')
            public, admin, portal, http_verify, native = [port() for _ in range(5)]
            key, system = secrets.token_hex(32), secrets.token_hex(32)
            env = dict(os.environ, HOPAE_TEST_GATEWAY_KEY=key, FIXTURE_KEY=key, HANGANG_ADMIN_TOKEN=system)
            config = json.loads((Path(__file__).resolve().parent.parent/'tests/fixtures/m1-basic.json').read_text())
            config['providers'] = []
            config['state_dir'] = str(root/'state')
            config['listen'] = {'portal': f'127.0.0.1:{portal}', 'gateway': f'127.0.0.1:{http_verify}', 'native_gateway': f'0.0.0.0:{native}', 'native_gateway_tls': {'certificate': str(root/'server.pem'), 'key': str(root/'server.key'), 'client_ca': str(root/'ca.pem')}}
            config['apps'][0]['ports'] = [public]
            (root/'hopae.json').write_text(json.dumps(config))
            route = {'id': 'owned', 'host': 'app.example.test', 'backends': [f'http://127.0.0.1:{origin.server_port}'], 'auth': {'url': f'http://127.0.0.1:{http_verify}/_hopae/verify', 'native': {'address': f'127.0.0.1:{native}', 'tls': {'server_name': 'hopae.example.test', 'ca': str(root/'ca.pem'), 'certificate': str(root/'client.pem'), 'key': str(root/'client.key')}}, 'request_headers': ['cookie', 'accept', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-site'], 'response_headers': ['x-forwarded-user'], 'static_request_headers': {'x-hopae-gateway-key': {'env': 'FIXTURE_KEY'}, 'x-hopae-contract': '1'}, 'forward_response': True, 'timeout_ms': 1000}}
            (root/'hangang.json').write_text(json.dumps({'http': [route]}))
            def start(binary, argv, name):
                log = open(root/(name+'.log'), 'wb')
                process = subprocess.Popen([str(binary.resolve()), *argv], env=env, stdout=log, stderr=log)
                processes.append(process)
                return process
            hopae = start(args.hopae_binary, ['run', '--config', str(root/'hopae.json')], 'hopae')
            def wait(url, process, name, authenticated=False):
                for _ in range(150):
                    if process.poll() is not None:
                        raise RuntimeError(name+' startup failed: '+(root/(name+'.log')).read_text())
                    try:
                        request = urllib.request.Request(url, headers={'Authorization': 'Bearer '+system} if authenticated else {})
                        with urllib.request.urlopen(request, timeout=1) as response:
                            if response.status == 200: return
                    except OSError:
                        time.sleep(.05)
                raise RuntimeError(name+' readiness deadline')
            wait(f'http://127.0.0.1:{portal}/healthz', hopae, 'hopae')
            context = ssl.create_default_context(cafile=str(root/'ca.pem'))
            context.set_alpn_protocols(['hop1'])
            try:
                with context.wrap_socket(socket.create_connection(('127.0.0.1', native), timeout=2), server_hostname='hopae.example.test') as unauthenticated:
                    unauthenticated.sendall(b'HOP1'+bytes(12))
                    unauthenticated.recv(16)
            except (ssl.SSLError, ConnectionError):
                pass
            else:
                raise AssertionError('missing client certificate was admitted')
            gateway = start(args.gateway_binary, ['--config', str(root/'hangang.json'), '--listen', f'127.0.0.1:{public}', '--admin', f'127.0.0.1:{admin}', '--tls-cert', str(root/'server.pem'), '--tls-key', str(root/'server.key'), '--threads', '2', '--lua-workers', '1'], 'hangang')
            wait(f'http://127.0.0.1:{admin}/v1/config', gateway, 'hangang', True)
            def request():
                c = http.client.HTTPSConnection('127.0.0.1', public, timeout=3, context=ssl.create_default_context(cafile=str(root/'ca.pem')))
                c.request('GET', '/private', headers={'Host': 'app.example.test', 'Accept': 'text/html', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Site': 'same-origin', 'x-forwarded-user': 'u_forged'})
                r = c.getresponse(); status, headers = r.status, dict(r.getheaders()); body = r.read(); c.close()
                if status not in (302,503): print("owned response reason:", body[:800].decode(errors="replace"))
                return status, headers
            for _ in range(2):
                status, headers = request()
                if status != 302:
                    for name in ['hangang', 'hopae']:
                        detail = (root/(name+'.log')).read_text().replace(key, '[redacted]').replace(system, '[redacted]')
                        print(name+' diagnostic: '+detail[-8000:])
                assert status == 302 and headers.get('location', '').startswith('https://auth.example.test/'), status
                assert not hits, 'anonymous/spoofed identity reached application'
            def change_server_name(name):
                address = f'http://127.0.0.1:{admin}/v1/config'
                headers = {'Authorization': 'Bearer '+system}
                with urllib.request.urlopen(urllib.request.Request(address, headers=headers), timeout=3) as response:
                    current = json.loads(response.read())
                current['http'][0]['auth']['native']['tls']['server_name'] = name
                headers.update({'Content-Type': 'application/json', 'If-Match': '"'+str(current['revision'])+'"'})
                request = urllib.request.Request(address, data=json.dumps(current).encode(), headers=headers, method='PUT')
                with urllib.request.urlopen(request, timeout=3) as response:
                    assert response.status == 200
            change_server_name('wrong.example.test')
            assert request()[0] == 503 and not hits, 'wrong TLS server name bypassed native verification'
            change_server_name('hopae.example.test')
            assert request()[0] == 302 and not hits, 'changed TLS settings did not rebuild the pool'
            hopae.terminate(); hopae.wait(timeout=10)
            status, _ = request()
            assert status == 503 and not hits, 'authority outage fell back to HTTP/upstream'
            print('PASS: real Hangang/Hopae processes, mTLS HOP1, persistent anonymous login redirects, required client certificate, wrong-name rejection/configuration recovery, spoofed identity isolation and outage fail-closed; no successful-login throughput claim.')
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
        origin.shutdown(); origin.server_close()


if __name__ == '__main__':
    main()
