"""Release contract tests use actual OpenSSL signatures and isolated fixture keys."""
import base64,importlib.util,json,subprocess,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('release',Path(__file__).with_name('prepare_release.py'));release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
EXPECTED_HUMAN_DOCS=('docs/HUMAN_NATIVE_CAPTURE.md', 'docs/ko/HUMAN_NATIVE_CAPTURE.md', 'docs/HUMAN_PROVIDER_OWNER.md', 'docs/ko/HUMAN_PROVIDER_OWNER.md', 'docs/HUMAN_IDENTITY_OWNER.md', 'docs/HUMAN_IDENTITY_OWNER.ko.md', 'docs/HUMAN_TOTP_PROVENANCE.md', 'docs/ko/HUMAN_TOTP_PROVENANCE.md', 'docs/HUMAN_NATIVE_INGRESS.md', 'docs/HUMAN_NATIVE_INGRESS.ko.md', 'docs/HUMAN_NATIVE_SOURCE.md', 'docs/HUMAN_NATIVE_SOURCE.ko.md', 'docs/HUMAN_PAIRED_PROJECTION.md', 'docs/HUMAN_PAIRED_PROJECTION.ko.md', 'crates/hopae-grpc/docs/HUMAN_OBSERVED_PROTOCOL.md', 'crates/hopae-grpc/docs/HUMAN_OBSERVED_PROTOCOL.ko.md')
class ReleaseTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.repo=self.root/'repo';self.repo.mkdir();self.output=self.root/'assets';self.key=self.root/'private.pem';self.signer=self.root/'signer';self.target='x86_64-unknown-linux-musl'
  self.real_run=subprocess.run;self.real_output=subprocess.check_output
  self.real_run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.key)],check=True,capture_output=True)
  public=self.real_output(['openssl','pkey','-in',str(self.key),'-pubout','-outform','DER'])[-32:];self.pin=base64.b64encode(public).decode();(self.repo/'release-public-key.txt').write_text(self.pin+'\n');(self.repo/'Cargo.toml').write_text('[package]\nversion="0.0.3"\n')
  binary=self.repo/'target'/self.target/'release/hopae';binary.parent.mkdir(parents=True);binary.write_bytes(b'qualified fixture executable')
  for name in ['LICENSE','README.md','README.ko.md','docs/HANGANG_NATIVE.md','docs/ko/HANGANG_NATIVE.md','docs/AUTH_GATEWAY.md','docs/ko/AUTH_GATEWAY.md','plugins/hopae/manifest.json','plugins/hopae/index.js','plugins/hopae/style.css']:
   p=self.repo/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('public fixture')
  for name in release.HUMAN_DOCS:
   path=self.repo/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('public Human contract '+name)
  private=self.repo/'docs/operator-private.env';private.write_text('never package fixture secret')
  p=patch.object(release,'ROOT',self.repo);p.start();self.addCleanup(p.stop)
  p=patch.object(subprocess,'check_output',side_effect=self.output_command);p.start();self.addCleanup(p.stop)
  p=patch.object(subprocess,'run',side_effect=self.run_command);p.start();self.addCleanup(p.stop)
  self.forge=False;self.dynamic=False
 def output_command(self,args,**kwargs):
  if args[0]=='readelf':return b'INTERP' if self.dynamic else b'LOAD'
  if args[1]=='--version':return 'hopae 0.0.3\n'
  if args[1]=='--public-key':return self.pin+'\n'
  return self.real_output(args,**kwargs)
 def run_command(self,args,**kwargs):
  if args[0]==str(self.signer):
   payload=Path(args[1]).read_bytes();signature=self.real_output(['openssl','pkeyutl','-sign','-inkey',str(self.key),'-rawin','-in',str(args[1])]);signature=bytes(64) if self.forge else signature
   Path(args[3]).write_text(json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(signature).decode()}));return subprocess.CompletedProcess(args,0)
  return self.real_run(args,**kwargs)
 def prepare(self):release.prepare(self.target,self.output,self.signer,self.key)
 def test_actual_signature_and_payload_binding(self):
  self.prepare();e=json.loads((self.output/('hopae-'+self.target+'.manifest.json')).read_text());p=json.loads(base64.b64decode(e['payload']));self.assertEqual(p['target'],self.target);self.assertEqual(p['artifact_url'],'https://github.com/ziozzang/hopae/releases/download/v0.0.3/hopae-'+self.target)
  with tarfile.open(next(self.output.glob('*.tar.gz'))) as archive:
   for name in ('docs/AUTH_GATEWAY.md','docs/ko/AUTH_GATEWAY.md'):
    self.assertEqual(archive.extractfile('hopae-v0.0.3-linux-amd64/'+name).read(),(self.repo/name).read_bytes())
 def test_human_archive_exact_paths_bytes_and_private_exclusion(self):
  expected=EXPECTED_HUMAN_DOCS
  self.prepare()
  with tarfile.open(next(self.output.glob('*.tar.gz'))) as archive:
   prefix='hopae-v0.0.3-linux-amd64/'
   expected_all={'hopae','LICENSE','README.md','README.ko.md','docs/HANGANG_NATIVE.md','docs/ko/HANGANG_NATIVE.md','docs/AUTH_GATEWAY.md','docs/ko/AUTH_GATEWAY.md','plugins/hopae/manifest.json','plugins/hopae/index.js','plugins/hopae/style.css'}|set(expected)
   self.assertEqual(set(archive.getnames()),{prefix+n for n in expected_all})
   self.assertEqual(len(archive.getmembers()),len(expected_all))
   for name in expected:self.assertEqual(archive.extractfile(prefix+name).read(),(self.repo/name).read_bytes())
   self.assertNotIn(prefix+'docs/operator-private.env',archive.getnames())
 def test_each_missing_human_contract_refuses_before_output(self):
  for name in EXPECTED_HUMAN_DOCS:
   with self.subTest(name=name):
    path=self.repo/name;data=path.read_bytes();path.unlink()
    with self.assertRaisesRegex(ValueError,'required Human'):self.prepare()
    self.assertFalse(self.output.exists());path.write_bytes(data)
 def test_unsigned_archive_deterministic_without_signer(self):
  release.prepare(self.target,self.output)
  second=self.root/'second';release.prepare(self.target,second)
  self.assertEqual(next(self.output.glob('*.tar.gz')).read_bytes(),next(second.glob('*.tar.gz')).read_bytes())
 def test_forged_signature_is_refused(self):
  self.forge=True
  with self.assertRaises(subprocess.CalledProcessError):self.prepare()
 def test_dynamic_loader_is_refused_before_output(self):
  self.dynamic=True
  with self.assertRaisesRegex(ValueError,'interpreter'):self.prepare()
  self.assertFalse(self.output.exists())
 def test_wrong_identity_is_refused_before_output(self):
  (self.repo/'release-public-key.txt').write_text('wrong identity')
  with self.assertRaisesRegex(ValueError,'identity'):self.prepare()
  self.assertFalse(self.output.exists())
 def test_output_cannot_contain_private_seed(self):
  self.output=self.root
  with self.assertRaisesRegex(ValueError,'separate'):self.prepare()
 def test_existing_output_is_preserved(self):
  self.output.mkdir();(self.output/'existing').write_text('preserve')
  with self.assertRaisesRegex(ValueError,'empty'):self.prepare()
  self.assertEqual((self.output/'existing').read_text(),'preserve')
if __name__=='__main__':unittest.main()
