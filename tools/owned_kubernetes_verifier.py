#!/usr/bin/env python3
"""Owned Pod TokenReview TLS mock for HTTP/HOP1 fixtures; no real JWT signature claim."""
import base64
import http.server
import json
import os
import tempfile
import pathlib
import socketserver
import ssl
import sys
import time
def publish_ready(path, port):
    """Publish complete canonical port bytes; existence is the readiness signal."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid owned verifier port")
    path = pathlib.Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(str(port))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)

class Handler(http.server.BaseHTTPRequestHandler):
    calls=0
    def log_message(self,*_):pass
    def do_GET(self):
        if self.headers.get('Authorization')!='Bearer owned-kubernetes-reviewer-at-least-thirty-two':self.send_response(403);self.end_headers();return
        expected={'/api/v1/namespaces/blue/serviceaccounts/worker':('worker','sa-1'),'/api/v1/namespaces/blue/pods/worker-pod':('worker-pod','pod-1')}
        if self.path not in expected:self.send_response(404);self.end_headers();return
        name,uid=expected[self.path]
        data=json.dumps({'apiVersion':'meta.k8s.io/v1','kind':'PartialObjectMetadata','metadata':{'name':name,'namespace':'blue','uid':uid}}).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
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
        if mode=='denied':reply['status']={'user':{},'error':'invalid fixture credential'}
        if mode=='wrong-uid':reply['status']['user']['uid']='other-service-account'
        data=json.dumps(reply).encode();self.send_response(201);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except OSError:pass
class Server(http.server.ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self);self.server_name='localhost';self.server_port=self.server_address[1]
def main():
    global root
    root = pathlib.Path(sys.argv[1])
    server = Server(('127.0.0.1', 0), Handler)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / 'server.pem', root / 'server.key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        publish_ready(root / 'ready', server.server_port)
        server.serve_forever()
    finally:
        server.server_close()

if __name__ == '__main__':
    main()
