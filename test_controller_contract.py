import base64, hashlib, tempfile, unittest
from pathlib import Path
from controller_contract import validate_native_source, artifact_manifest, signing_identity, verify_lockfile

class BoundaryTests(unittest.TestCase):
    def source(self):
        raw=b'tree '+b'a'*40+b'\nauthor Synthetic <test@example.invalid> 1 +0000\ncommitter Synthetic <test@example.invalid> 1 +0000\n\nfixture\n'
        return dict(packageLockSha256='d'*64,originalCommit=hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),sourceTree='a'*40,snapshotCommit='b'*40,originalCommitObjectBase64=base64.b64encode(raw).decode(),originalCommitObjectSha256=hashlib.sha256(raw).hexdigest())
    def test_native_identity(self):
        self.assertTrue(validate_native_source(self.source())['nativeCommitObjectVerified'])
    def test_wrong_tree(self):
        d=self.source();d['sourceTree']='c'*40
        with self.assertRaises(ValueError):validate_native_source(d)
    def test_mutable_signer(self):
        with self.assertRaises(ValueError):signing_identity('owner','controller','main')
    def test_artifact_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);(r/'x').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):artifact_manifest(r)
    def test_environment_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);(r/'.env').write_text('synthetic')
            with self.assertRaises(ValueError):artifact_manifest(r)
    def test_registry_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            lock={'lockfileVersion':3,'packages':{'node_modules/x':{'resolved':'https://user@registry.npmjs.org/x','integrity':'sha512-YQ=='}}}
            with self.assertRaises(ValueError):verify_lockfile(lock,Path(d))
    def test_registry_nonstandard_port(self):
        with tempfile.TemporaryDirectory() as d:
            lock={'lockfileVersion':3,'packages':{'node_modules/x':{'resolved':'https://registry.npmjs.org:444/x','integrity':'sha512-YQ=='}}}
            with self.assertRaises(ValueError):verify_lockfile(lock,Path(d))
    def test_artifact_hardlink(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);(r/'first').write_text('fixture');os.link(r/'first',r/'second')
            with self.assertRaises(ValueError):artifact_manifest(r)
    def test_local_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            lock={'lockfileVersion':3,'packages':{'node_modules/x':{'resolved':'vendor/../outside'}}}
            with self.assertRaises(ValueError):verify_lockfile(lock,Path(d))
    def test_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);(r/'index.html').write_text('fixture')
            self.assertEqual(len(artifact_manifest(r)['files']),1)

if __name__=='__main__':unittest.main()
