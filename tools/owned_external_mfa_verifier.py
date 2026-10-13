#!/usr/bin/env python3
"""Owned loopback HTTPS fixture only. No credential/body logging or outbound calls."""
import http.server
import json
import pathlib
import socketserver
import ssl
import sys
import uuid

root = pathlib.Path(sys.argv[1])


class Handler(http.server.BaseHTTPRequestHandler):
    calls = 0

    def log_message(self, *_):
        pass

    def do_POST(self):
        if self.path != '/verify' or self.headers.get('x-hopae-verifier-key') != 'owned-verifier-key-at-least-thirty-two-bytes':
            self.send_error(403)
            return
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 16384:
            self.send_error(400)
            return
        request = json.loads(self.rfile.read(length))
        type(self).calls += 1
        (root / 'calls').write_text(str(type(self).calls))
        keys = ('challenge', 'user', 'session', 'service', 'factor',
                'configuration_revision', 'credential_generation')
        reply = {key: request[key] for key in keys}
        reply.update(active=request['response'] == 'approve', proof_id=uuid.uuid4().hex,
                     expires_at=request['verification_started_at'] + 2000)
        if request['response'] == 'cross':
            reply['user'] = 'other-user'
        if request['response'] == 'aal':
            reply['aal'] = 2
        body = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LoopbackServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer normally performs getfqdn() during startup. An owned
        # loopback fixture must not depend on DNS availability or its timeout.
        socketserver.TCPServer.server_bind(self)
        self.server_name = 'localhost'
        self.server_port = self.server_address[1]


server = LoopbackServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / 'server.pem', root / 'server.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
(root / 'ready').write_text(str(server.server_port))
server.serve_forever()
