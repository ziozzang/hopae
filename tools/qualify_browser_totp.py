#!/usr/bin/env python3
"""Actual Chromium MFA qualification on a private, isolated candidate state copy.
The first-factor session is an owned fixture, not external Google authentication.
Requires Playwright and a running loopback candidate with the reserved canary app.
"""
import asyncio,base64,hashlib,hmac,json,os,pathlib,secrets,sqlite3,struct,sys,time,urllib.request,urllib.error
from urllib.parse import urlparse
from playwright.async_api import async_playwright
os.umask(0o077)
root=pathlib.Path(sys.argv[1]).resolve()
if not root.name.startswith('hopae-v5-candidate-') or not root.is_dir():raise SystemExit('private candidate directory required')
database=root/'state/hopae.db'
if database.is_symlink() or database.resolve()!=database or database.stat().st_nlink!=1:raise SystemExit('independent candidate database required')
if root.stat().st_mode & 0o077:raise SystemExit('candidate directory must be private')
cfg=json.loads((root/'candidate.json').read_text());env=dict(l.split('=',1)for l in (root/'candidate.env').read_text().splitlines()if '='in l)
if cfg.get('cookie',{}).get('secure',True) is not True:raise SystemExit('secure candidate cookies required')
import ipaddress
for listener in ['portal','gateway']:
 if not ipaddress.ip_address(cfg['listen'][listener].rsplit(':',1)[0]).is_loopback:raise SystemExit('loopback candidate listeners required')
portal_endpoint='http://'+cfg['listen']['portal'];gateway_endpoint='http://'+cfg['listen']['gateway']
portal=urlparse(cfg['portal']['public_url']).hostname;app='mfa-canary.example.test';name=cfg.get('cookie',{}).get('name','__Host-hopae' if cfg.get('cookie',{}).get('secure',True) else 'hopae');caller=env[cfg['gateway']['caller_key_env']]
def token(n):return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip('=')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
http=urllib.request.build_opener(NoRedirect())
def fetch(url,method='GET',headers=None,data=None):
 req=urllib.request.Request(url,headers=headers or {},data=data,method=method)
 try:r=http.open(req,timeout=8)
 except urllib.error.HTTPError as e:r=e
 with r:return r.status,list(r.headers.items()),r.read()
def code_for(seed):
 counter=int(time.time())//30;d=hmac.new(seed,struct.pack('!Q',counter),'sha1').digest();o=d[-1]&15
 return f'{(struct.unpack("!I",d[o:o+4])[0]&0x7fffffff)%1000000:06d}'
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(executable_path=os.environ.get('HOPAE_QUALIFY_CHROMIUM'),headless=True,args=['--no-sandbox'])
  ctx=await browser.new_context(ignore_https_errors=False);page=await ctx.new_page();ua=await page.evaluate('navigator.userAgent')
  now=int(time.time());uid='u_canary_'+secrets.token_hex(12);sid='s_canary_'+secrets.token_hex(12);portal_handle='v1.'+token(32);app_handle='v1.'+token(32)
  with sqlite3.connect(root/'state/hopae.db')as db:
   provider=db.execute("SELECT provider_id FROM providers WHERE kind='oidc' AND enabled=1 AND deleted_at IS NULL LIMIT 1").fetchone()[0]
   db.execute('INSERT INTO users(user_id,primary_email,email_verified,display_name,status,authz_version,groups,created_at,updated_at) VALUES(?,?,1,?,\'active\',1,\'[]\',?,?)',(uid,uid+'@example.test','Owned browser fixture',now,now))
   snapshot=json.dumps({'email':None,'display_name':'Owned browser fixture','username':None,'groups':[]})
   factors=json.dumps([{'kind':'oidc','provider':provider,'at':now*1000}],separators=(',',':'))
   db.execute('INSERT INTO sessions(session_id,user_id,provider_id,auth_time,factors,aal,authz_version,cred_gen,snapshot,bound_ip,bound_ua_sha256,created_at,last_seen_at,absolute_expires_at,authz_version_at_auth,auth_time_source) VALUES(?,?,?,?,?,1,1,1,?,\'127.0.0.1\',?,?,?,?,1,\'hopae_completion\')',(sid,uid,provider,now,factors,snapshot,hashlib.sha256(ua.encode()).digest(),now,now,now+3600))
   for host,handle in [(portal,portal_handle),(app,app_handle)]:db.execute('INSERT INTO session_handles(handle_sha256,session_id,host,issued_aal,created_at,last_seen_at,absolute_expires_at) VALUES(?,?,?,1,?,?,?)',(hashlib.sha256(handle.encode()).digest(),sid,host,now,now,now+3600))
  await ctx.add_cookies([{'name':name,'value':value,'domain':host,'path':'/','secure':True,'httpOnly':True,'sameSite':'Lax'}for host,value in [(portal,portal_handle),(app,app_handle)]])
  phases=[];diagnostics=[]
  async def route(r):
   req=r.request;u=urlparse(req.url);headers=dict(req.headers)
   diagnostics.append({'host_kind':'portal' if u.hostname==portal else 'app','path':u.path,'stage':'request'})
   if u.hostname==portal:
    headers.update({'host':portal,'x-forwarded-proto':'https','x-forwarded-for':'127.0.0.1'})
    status,hs,body=fetch(portal_endpoint+u.path+('?' +u.query if u.query else ''),req.method,headers,req.post_data_buffer)
   elif u.hostname==app:
    h={'x-hopae-contract':'1','x-hopae-gateway-key':caller,'x-forwarded-host':app,'x-forwarded-proto':'https','x-forwarded-port':'443','x-forwarded-for':'127.0.0.1','x-original-url':req.url,'x-original-method':req.method,'x-original-uri':u.path+('?' +u.query if u.query else ''),'accept':headers.get('accept','text/html'),'user-agent':ua}
    if req.resource_type=='Document':h.update({'sec-fetch-mode':'navigate','sec-fetch-dest':'document','sec-fetch-site':'same-site'})
    for k in ['cookie','sec-fetch-mode','sec-fetch-dest','sec-fetch-site']:
     if k in headers:h[k]=headers[k]
    status,hs,body=fetch(gateway_endpoint+'/_hopae/verify',headers=h)
    diagnostics.append({'status':status,'aal':dict((k.lower(),v)for k,v in hs).get('x-hopae-aal'),'stage':'app_verify'})
    (root/'browser-diagnostics.json').write_text(json.dumps(diagnostics))
    if status==200:
     assert dict((k.lower(),v)for k,v in hs).get('x-hopae-aal')=='2';body=b'<h1>Owned protected resource: AAL 2</h1>';hs=[('content-type','text/html'),('cache-control','no-store')]
   else:await r.abort();return
   diagnostics.append({'status':status,'stage':'response','path':u.path,'origin_present':'origin' in headers,'origin_null':headers.get('origin')=='null','referrer_policy':dict((k.lower(),v)for k,v in hs).get('referrer-policy')})
   (root/'browser-diagnostics.json').write_text(json.dumps(diagnostics))
   # CDP Fetch keeps separate Set-Cookie fields; flattening headers loses cookies.
   hs=[{'name':k,'value':v}for k,v in hs if k.lower()not in ['content-length','transfer-encoding','connection','content-encoding']]
   await cdp.send('Fetch.fulfillRequest',{'requestId':r.id,'responseCode':status,'responseHeaders':hs,'body':base64.b64encode(body).decode()})
  # Use CDP interception to preserve multiple Set-Cookie fields and browser Origin.
  cdp=await ctx.new_cdp_session(page)
  async def paused(event):
   class R:
    id=event['requestId']
    async def abort(self):await cdp.send('Fetch.failRequest',{'requestId':self.id,'errorReason':'BlockedByClient'})
   class Req:
    resource_type=event.get('resourceType');url=event['request']['url'];method=event['request']['method'];headers={k.lower():v for k,v in event['request']['headers'].items()};post_data_buffer=event['request'].get('postData','').encode()if method=='POST'else None
   r=R();r.request=Req();await route(r)
  errors=[]
  async def safe_paused(event):
   try:await paused(event)
   except Exception as e:errors.append(type(e).__name__);(root/'browser-diagnostics.json').write_text(json.dumps({'requests':diagnostics,'error_types':errors}));await cdp.send('Fetch.failRequest',{'requestId':event['requestId'],'errorReason':'Failed'})
  cdp.on('Fetch.requestPaused',lambda event:asyncio.create_task(safe_paused(event)))
  await cdp.send('Fetch.enable',{'patterns':[{'urlPattern':'https://'+portal+'/*'},{'urlPattern':'https://'+app+'/*'}]})
  await page.goto('https://'+portal+'/security/totp');await page.locator('form button').click();await page.wait_for_selector('#totp-key')
  setup=await page.locator('#totp-key').input_value();seed=base64.b32decode(setup+'='*((8-len(setup)%8)%8));await page.locator('#totp-code').fill(code_for(seed));await page.locator('form button').click();await page.wait_for_url('**/security/totp/confirm')
  assert await page.locator('#totp-key').count()==0;phases.append('actual_chromium_enrollment')
  initial_counter=int(time.time())//30
  while int(time.time())//30==initial_counter:await asyncio.sleep(.2)
  await page.goto('https://'+app+'/protected');await page.wait_for_selector('#stepup-code')
  assert urlparse(page.url).path=='/stepup';await page.screenshot(path=str(root/'stepup-before-code.png'))
  await page.locator('#stepup-code').fill(code_for(seed));await page.locator('form button').click();await page.wait_for_url('https://'+app+'/protected')
  assert await page.locator('h1').inner_text()=='Owned protected resource: AAL 2';phases.append('actual_chromium_stepup_and_handoff')
  status,hs,_=fetch(gateway_endpoint+'/_hopae/verify',headers={'x-hopae-contract':'1','x-hopae-gateway-key':caller,'x-forwarded-host':app,'x-forwarded-proto':'https','x-forwarded-port':'443','x-forwarded-for':'127.0.0.1','x-original-url':'https://'+app+'/protected','x-original-method':'GET','x-original-uri':'/protected','accept':'application/json','cookie':name+'='+app_handle,'user-agent':ua})
  assert status==401;phases.append('previous_handle_refused')
  assert not errors
  (root/'browser-report.json').write_text(json.dumps({'phases':phases,'first_factor':'owned session fixture on private owner-state copy; not real Google authentication','actual_chromium':True,'production_changed':False},indent=2)+'\n')
  await browser.close()
asyncio.run(main())
