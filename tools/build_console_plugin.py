#!/usr/bin/env python3
"""Hash the trusted Hopae console package; no deployment credentials."""
from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parents[1]/'plugins/hopae'
routes=[('status','GET',False),('me','GET',False)]
routes += [(v+'/query','POST',False) for v in ('users','sessions','events')]
routes += [(v,'POST',True) for v in ('users/disable','users/enable','users/sessions-terminate','sessions/terminate')]
manifest={'id':'hopae','name':'Hopae','version':'0.1.2','api_version':1,'entry':'index.js','assets':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in ('index.js','style.css')},'routes':[{'path':p,'method':m,'mutation':w} for p,m,w in routes]}
(root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for f in root.iterdir():f.chmod(0o644)
print('Hopae console manifest SHA-256:',hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest())
