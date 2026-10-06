import copy,hashlib,hmac,tempfile,unittest
from pathlib import Path
from release_gate import decide,signed_payload
class GateTests(unittest.TestCase):
 def test_all_decisions(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'artifact';p.write_bytes(b'candidate build')
   good={'policySha256':'trusted-policy','sourceCommit':'a'*40,'testedCommit':'a'*40,'controllerAttested':True,'checks':{'authz':'PASS','tenant':'PASS'},'artifactSha256':hashlib.sha256(p.read_bytes()).hexdigest()}
   key=b'test-only-key-not-production-credential!'
   good['signature']=hmac.new(key,signed_payload(good),hashlib.sha256).hexdigest()
   self.assertTrue(decide(good,p,['authz','tenant'],'trusted-policy',attestation_key=key)['allowPublication'])
   forged=copy.deepcopy(good);forged.pop('signature')
   self.assertFalse(decide(forged,p,['authz','tenant'],'trusted-policy',attestation_key=key)['allowPublication'])
   for key,value in [('policySha256','changed'),('testedCommit','b'*40),('controllerAttested',False),('checks',{'authz':'FAIL','tenant':'PASS'}),('checks',{'authz':'PASS'}),('artifactSha256','0'*64)]:
    bad=copy.deepcopy(good);bad[key]=value
    self.assertFalse(decide(bad,p,['authz','tenant'],'trusted-policy',attestation_key=key)['allowPublication'],key)
   p.write_bytes(b'changed artifact')
   self.assertFalse(decide(good,p,['authz','tenant'],'trusted-policy',attestation_key=key)['allowPublication'])
if __name__=='__main__':unittest.main()
