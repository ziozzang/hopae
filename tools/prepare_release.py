#!/usr/bin/env python3
"""Stage deterministic qualified Hopae artifacts; publication is separate."""
import argparse,base64,gzip,hashlib,json,subprocess,tarfile,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TARGETS={'x86_64-unknown-linux-musl':('linux','amd64'),'aarch64-unknown-linux-musl':('linux','arm64'),'x86_64-apple-darwin':('darwin','amd64'),'aarch64-apple-darwin':('darwin','arm64')}
def prepare(target,output,signer=None,seed=None):
 platform,arch=TARGETS[target];version=tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
 binary=ROOT/'target'/target/'release/hopae'
 if subprocess.check_output([str(binary),'--version'],text=True).strip()!='hopae '+version:raise ValueError('binary version mismatch')
 if output.exists() and any(output.iterdir()):raise ValueError('output must be empty')
 output.mkdir(parents=True,exist_ok=True);raw=output/('hopae-'+target);raw.write_bytes(binary.read_bytes());raw.chmod(0o755)
 folder=f'hopae-v{version}-{platform}-{arch}'
 sources={'hopae':binary,'LICENSE':ROOT/'LICENSE','README.md':ROOT/'README.md','README.ko.md':ROOT/'README.ko.md','docs/HANGANG_NATIVE.md':ROOT/'docs/HANGANG_NATIVE.md','docs/ko/HANGANG_NATIVE.md':ROOT/'docs/ko/HANGANG_NATIVE.md'}
 for name in ('manifest.json','index.js','style.css'):sources['plugins/hopae/'+name]=ROOT/'plugins/hopae'/name
 with (output/(folder+'.tar.gz')).open('wb') as f,gzip.GzipFile(fileobj=f,mode='wb',filename='',mtime=0) as gz,tarfile.open(fileobj=gz,mode='w') as tar:
  for name,path in sources.items():
   info=tarfile.TarInfo(folder+'/'+name);info.size=path.stat().st_size;info.mode=0o755 if name=='hopae' else 0o644;info.mtime=0;info.uid=info.gid=0
   with path.open('rb') as source:tar.addfile(info,source)
 if signer is not None:
  pin=(ROOT/'release-public-key.txt').read_text().strip()
  reported=subprocess.check_output([str(signer.resolve()),'--public-key',str(seed.resolve())],text=True).strip()
  if reported!=pin:raise ValueError('signing identity does not match repository pin')
  payload={'version':version,'target':target,'artifact_url':f'https://github.com/ziozzang/hopae/releases/download/v{version}/{raw.name}','sha256':hashlib.sha256(raw.read_bytes()).hexdigest(),'size':raw.stat().st_size}
  temporary=output/'.release-payload.json';temporary.write_text(json.dumps(payload,separators=(',',':')))
  manifest=output/(raw.name+'.manifest.json')
  try:subprocess.run([str(signer.resolve()),str(temporary.resolve()),str(seed.resolve()),str(manifest.resolve())],check=True,capture_output=True)
  finally:temporary.unlink(missing_ok=True)
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
  envelope=json.loads(manifest.read_text());encoded=base64.b64decode(envelope['payload'],validate=True)
  Ed25519PublicKey.from_public_bytes(base64.b64decode(pin,validate=True)).verify(base64.b64decode(envelope['signature'],validate=True),encoded)
  if json.loads(encoded)!=payload:raise ValueError('signed payload differs from qualified artifact')
  (output/'release-public-key.txt').write_text(pin+'\n')
 files=sorted(output.iterdir());(output/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
 print('Staged',target,'version',version)
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--target',choices=TARGETS,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--signer',type=Path);parser.add_argument('--seed',type=Path);args=parser.parse_args();
 if (args.signer is None)!=(args.seed is None):parser.error('signer and private seed must be supplied together')
 prepare(args.target,args.output,args.signer,args.seed)
