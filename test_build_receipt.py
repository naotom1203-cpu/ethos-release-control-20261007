import copy,tempfile,unittest
from pathlib import Path
import test_controller_contract
from controller_contract import artifact_manifest
from assemble_build_receipt import assemble
from sandbox_build import IMAGE
class ReceiptTests(unittest.TestCase):
    def fixture(self,root):
        (root/'index.html').write_text('synthetic artifact')
        source=test_controller_contract.BoundaryTests().source()
        result={'artifactManifest':artifact_manifest(root),'buildPassed':True,'typecheckPassed':True,'sourceBuildSandbox':'no-network-no-credentials-non-root','image':IMAGE,'registryAuditVulnerabilities':{k:0 for k in ['info','low','moderate','high','critical','total']},'allReviewedPrebuildChecksExecuted':True,'auditedLockfileSha256':source['packageLockSha256'],'registryAuditResponseSha256':'e'*64}
        return source,result
    def test_exact_content_binding(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source,result=self.fixture(root)
            self.assertEqual(assemble(source,result,root,'owner','controller','a'*40)['source']['originalCommit'],source['originalCommit'])
    def test_changed_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source,result=self.fixture(root);(root/'index.html').write_text('tampered artifact')
            with self.assertRaises(ValueError):assemble(source,result,root,'owner','controller','a'*40)
    def test_audit_failure_or_wrong_lock_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source,result=self.fixture(root)
            for field,value in [('allReviewedPrebuildChecksExecuted',False),('auditedLockfileSha256','f'*64),('registryAuditVulnerabilities',{})]:
                changed=copy.deepcopy(result);changed[field]=value
                with self.assertRaises(ValueError):assemble(source,changed,root,'owner','controller','a'*40)
if __name__=='__main__':unittest.main()
