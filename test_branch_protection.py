import copy,unittest
from controller_contract import verify_branch_protection
class ProtectionTests(unittest.TestCase):
    def setUp(self):self.d={'required_status_checks':{'strict':True,'contexts':['controller-boundaries']},'enforce_admins':{'enabled':True},'allow_force_pushes':{'enabled':False},'allow_deletions':{'enabled':False},'required_pull_request_reviews':{'required_approving_review_count':0}}
    def test_complete_config(self):self.assertTrue(verify_branch_protection(self.d,['controller-boundaries'])['adminsEnforced'])
    def test_missing_required_check(self):
        with self.assertRaises(ValueError):verify_branch_protection(self.d,['unknown'])
    def test_bypass_rejected(self):
        for field,value in [('enforce_admins',False),('allow_force_pushes',True),('allow_deletions',True)]:
            d=copy.deepcopy(self.d);d[field]['enabled']=value
            with self.assertRaises(ValueError):verify_branch_protection(d,['controller-boundaries'])
if __name__=='__main__':unittest.main()
