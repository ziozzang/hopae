#!/usr/bin/env python3
"""Stage deterministic qualified Hopae artifacts; publication is separate."""
import argparse,base64,gzip,hashlib,json,subprocess,tarfile,tempfile,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TARGETS={'x86_64-unknown-linux-musl':('linux','amd64'),'aarch64-unknown-linux-musl':('linux','arm64'),'x86_64-apple-darwin':('darwin','amd64'),'aarch64-apple-darwin':('darwin','arm64')}
# Explicit public contracts only; never recursively package local evidence or keys.
HUMAN_DOCS=('docs/HUMAN_NATIVE_CAPTURE.md', 'docs/ko/HUMAN_NATIVE_CAPTURE.md', 'docs/HUMAN_PROVIDER_OWNER.md', 'docs/ko/HUMAN_PROVIDER_OWNER.md', 'docs/HUMAN_IDENTITY_OWNER.md', 'docs/HUMAN_IDENTITY_OWNER.ko.md', 'docs/HUMAN_TOTP_PROVENANCE.md', 'docs/ko/HUMAN_TOTP_PROVENANCE.md', 'docs/HUMAN_NATIVE_INGRESS.md', 'docs/HUMAN_NATIVE_INGRESS.ko.md', 'docs/HUMAN_NATIVE_SOURCE.md', 'docs/HUMAN_NATIVE_SOURCE.ko.md', 'docs/HUMAN_PAIRED_PROJECTION.md', 'docs/HUMAN_PAIRED_PROJECTION.ko.md', 'crates/hopae-grpc/docs/HUMAN_OBSERVED_PROTOCOL.md', 'crates/hopae-grpc/docs/HUMAN_OBSERVED_PROTOCOL.ko.md')
def prepare(target,output,signer=None,seed=None):
 platform,arch=TARGETS[target];version=tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
 binary=ROOT/'target'/target/'release/hopae'
 if target.endswith('-musl') and b'INTERP' in subprocess.check_output(['readelf','-lW',str(binary)]):raise ValueError('static release must not require an ELF interpreter')
 if subprocess.check_output([str(binary),'--version'],text=True).strip()!='hopae '+version:raise ValueError('binary version mismatch')
 if (signer is None)!=(seed is None):raise ValueError('signer and seed must be supplied together')
 if signer is not None:
  if output.resolve()==seed.resolve() or output.resolve() in seed.resolve().parents or seed.resolve() in output.resolve().parents:raise ValueError('output must be separate from signing seed')
  pin=(ROOT/'release-public-key.txt').read_text().strip()
  reported=subprocess.check_output([str(signer.resolve()),'--public-key',str(seed.resolve())],text=True).strip()
  if reported!=pin:raise ValueError('signing identity does not match repository pin')
 if output.exists() and any(output.iterdir()):raise ValueError('output must be empty')
 for name in HUMAN_DOCS:
  if not (ROOT/name).is_file():raise ValueError('required Human release documentation missing: '+name)
 output.mkdir(parents=True,exist_ok=True);raw=output/('hopae-'+target);raw.write_bytes(binary.read_bytes());raw.chmod(0o755)
 folder=f'hopae-v{version}-{platform}-{arch}'
 sources={'hopae':binary,'LICENSE':ROOT/'LICENSE','README.md':ROOT/'README.md','README.ko.md':ROOT/'README.ko.md','docs/HANGANG_NATIVE.md':ROOT/'docs/HANGANG_NATIVE.md','docs/ko/HANGANG_NATIVE.md':ROOT/'docs/ko/HANGANG_NATIVE.md'}
 for name in ('docs/AUTH_GATEWAY.md','docs/ko/AUTH_GATEWAY.md')+HUMAN_DOCS:sources[name]=ROOT/name
 for name in ('manifest.json','index.js','style.css'):sources['plugins/hopae/'+name]=ROOT/'plugins/hopae'/name
 with (output/(folder+'.tar.gz')).open('wb') as f,gzip.GzipFile(fileobj=f,mode='wb',filename='',mtime=0) as gz,tarfile.open(fileobj=gz,mode='w') as tar:
  for name,path in sources.items():
   info=tarfile.TarInfo(folder+'/'+name);info.size=path.stat().st_size;info.mode=0o755 if name=='hopae' else 0o644;info.mtime=0;info.uid=info.gid=0
   with path.open('rb') as source:tar.addfile(info,source)
 if signer is not None:
  payload={'version':version,'target':target,'artifact_url':f'https://github.com/ziozzang/hopae/releases/download/v{version}/{raw.name}','sha256':hashlib.sha256(raw.read_bytes()).hexdigest(),'size':raw.stat().st_size}
  temporary=output/'.release-payload.json';temporary.write_text(json.dumps(payload,separators=(',',':')))
  manifest=output/(raw.name+'.manifest.json')
  try:subprocess.run([str(signer.resolve()),str(temporary.resolve()),str(seed.resolve()),str(manifest.resolve())],check=True,capture_output=True)
  finally:temporary.unlink(missing_ok=True)
  envelope=json.loads(manifest.read_text());encoded=base64.b64decode(envelope['payload'],validate=True)
  with tempfile.TemporaryDirectory(prefix='hopae-signature-') as directory:
   directory=Path(directory);(directory/'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+base64.b64decode(pin,validate=True));(directory/'payload').write_bytes(encoded);(directory/'signature').write_bytes(base64.b64decode(envelope['signature'],validate=True))
   subprocess.run(['openssl','pkeyutl','-verify','-pubin','-keyform','DER','-inkey',str(directory/'public.der'),'-rawin','-in',str(directory/'payload'),'-sigfile',str(directory/'signature')],check=True,capture_output=True)
  if json.loads(encoded)!=payload:raise ValueError('signed payload differs from qualified artifact')
  (output/'release-public-key.txt').write_text(pin+'\n')
 files=sorted(output.iterdir());(output/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
 print('Staged',target,'version',version)
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--target',choices=TARGETS,default='x86_64-unknown-linux-musl');parser.add_argument('--output',type=Path,required=True);parser.add_argument('--signer',type=Path);parser.add_argument('--seed',type=Path);args=parser.parse_args();
 if (args.signer is None)!=(args.seed is None):parser.error('signer and private seed must be supplied together')
 prepare(args.target,args.output,args.signer,args.seed)
