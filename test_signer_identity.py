import copy,unittest
from read_signer_identity import validate_claims
class IdentityTests(unittest.TestCase):
    def setUp(self):
        sha='a'*40
        self.claims={'iss':'https://token.actions.githubusercontent.com','aud':'sigstore','repository':'naotom1203-cpu/ethos-recovery','job_workflow_sha':sha,'job_workflow_ref':'naotom1203-cpu/ethos-release-control-20261007/.github/workflows/protected-build.yml@'+sha}
    def test_exact_immutable_signer(self):self.assertEqual(validate_claims(self.claims)['workflowSha'],'a'*40)
    def test_branch_or_foreign_workflow_rejected(self):
        for value in ['naotom1203-cpu/ethos-release-control-20261007/.github/workflows/protected-build.yml@refs/heads/main','other/repo/.github/workflows/protected-build.yml@'+'a'*40]:
            d=copy.deepcopy(self.claims);d['job_workflow_ref']=value
            with self.assertRaises(ValueError):validate_claims(d)
    def test_unapproved_caller_rejected(self):
        self.claims['repository']='other/production'
        with self.assertRaises(ValueError):validate_claims(self.claims)
    def test_wrong_audience_rejected(self):
        self.claims['aud']='other'
        with self.assertRaises(ValueError):validate_claims(self.claims)
if __name__=='__main__':unittest.main()
