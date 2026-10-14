#!/usr/bin/env python3
"""Owned Pod TokenReview TLS mock for HTTP/HOP1 fixtures; no real JWT signature claim."""
import base64
import http.server
import json
import pathlib
import socketserver
import ssl
import sys
import time
root=pathlib.Path(sys.argv[1])
class Handler(http.server.BaseHTTPRequestHandler):
    calls=0
    def log_message(self,*_):pass
    def do_POST(self):
        if self.path!='/apis/authentication.k8s.io/v1/tokenreviews' or self.headers.get('Authorization')!='Bearer owned-kubernetes-reviewer-at-least-thirty-two':
            self.send_response(403);self.end_headers();return
        length=int(self.headers.get('Content-Length','0'))
        if not 0<length<=16384:self.send_response(400);self.end_headers();return
        body=json.loads(self.rfile.read(length));assert body['spec']['audiences']==['orders-workload']
        encoded=body['spec']['token'].split('.')[1];claims=json.loads(base64.urlsafe_b64decode(encoded+'='*((4-len(encoded)%4)%4)));k=claims['kubernetes.io']
        type(self).calls+=1;(root/'calls').write_text(str(type(self).calls))
        mode=(root/'mode').read_text().strip()
        if mode=='hold':
            (root/'entered').write_text('yes');deadline=time.monotonic()+5
            while not (root/'release').exists() and time.monotonic()<deadline:time.sleep(.005)
        if mode=='unavailable':self.send_response(503);self.end_headers();return
        reply={'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','status':{'authenticated':mode!='denied','audiences':['orders-workload'],'user':{'username':claims['sub'],'uid':k['serviceaccount']['uid'],'extra':{'authentication.kubernetes.io/pod-name':[k['pod']['name']],'authentication.kubernetes.io/pod-uid':[k['pod']['uid']]}}}}
        if mode=='wrong-uid':reply['status']['user']['uid']='other-service-account'
        data=json.dumps(reply).encode();self.send_response(201);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except OSError:pass
class Server(http.server.ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self);self.server_name='localhost';self.server_port=self.server_address[1]
server=Server(('127.0.0.1',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'server.pem',root/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True);(root/'ready').write_text(str(server.server_port));server.serve_forever()
