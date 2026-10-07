import base64,hashlib,json,subprocess,tempfile,unittest
from pathlib import Path
from prepare_native_source import prepare

class NativeSourceTests(unittest.TestCase):
    def fixture(self,root):
        def git(*args):return subprocess.check_output(['git','-C',str(root),*args]).decode().strip()
        git('init','-q');git('config','user.name','Synthetic');git('config','user.email','test@example.invalid')
        lock={'lockfileVersion':3,'packages':{'':{'name':'fixture'},'node_modules/x':{'version':'1','resolved':'https://registry.npmjs.org/x/-/x-1.tgz','integrity':'sha512-YQ=='}}}
        (root/'package-lock.json').write_text(json.dumps(lock));git('add','.');git('commit','-qm','snapshot')
        tree=git('rev-parse','HEAD^{tree}');snapshot=git('rev-parse','HEAD')
        raw=('tree '+tree+'\nauthor Native <native@example.invalid> 1 +0000\ncommitter Native <native@example.invalid> 1 +0000\n\nnative fixture\n').encode()
        return dict(packageLockSha256=hashlib.sha256((root/'package-lock.json').read_bytes()).hexdigest(),originalCommit=hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),sourceTree=tree,snapshotCommit=snapshot,originalCommitObjectBase64=base64.b64encode(raw).decode(),originalCommitObjectSha256=hashlib.sha256(raw).hexdigest())
    def test_isolated_identity_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);doc=self.fixture(root);before=(root/'package-lock.json').read_bytes()
            result=prepare(root,doc)
            self.assertFalse(result['productFilesChanged']);self.assertEqual(before,(root/'package-lock.json').read_bytes())
            self.assertEqual(subprocess.check_output(['git','-C',d,'rev-parse','HEAD']).decode().strip(),doc['originalCommit'])
    def test_dirty_source_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);doc=self.fixture(root);(root/'unreviewed').write_text('fixture')
            with self.assertRaises(ValueError):prepare(root,doc)
    def test_wrong_snapshot_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);doc=self.fixture(root);doc['snapshotCommit']='c'*40
            with self.assertRaises(ValueError):prepare(root,doc)

if __name__=='__main__':unittest.main()
