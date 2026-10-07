import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
import test_build_receipt
from controller_contract import validate_native_source,signing_identity
class SigningSourceTests(unittest.TestCase):
 def execute(self,alter=None):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);out=root/'output';out.mkdir()
   source,result=test_build_receipt.ReceiptTests().fixture(out)
   expected=copy.deepcopy(source);validation={'source':validate_native_source(source)}
   if alter=='caller':expected['snapshotCommit']='c'*40
   if alter=='validation':validation['source']['snapshotCommit']='c'*40
   identity={'callerRepository':'naotom1203-cpu/ethos-recovery','issuer':'https://token.actions.githubusercontent.com','owner':'owner','repository':'controller','workflowSha':'a'*40,'identity':signing_identity('owner','controller','a'*40)}
   for name,value in [('source',source),('result',result),('expected',expected),('validation',validation),('identity',identity)]: (root/name).write_text(json.dumps(value))
   args=[sys.executable,str(Path(__file__).parent/'create_receipt_from_identity.py'),str(root/'source'),str(root/'result'),str(out),str(root/'identity'),str(root/'receipt'),str(root/'expected'),str(root/'validation')]
   process=subprocess.run(args,capture_output=True)
   return process.returncode,(root/'receipt').exists()
 def test_matching_independent_contract(self):self.assertEqual(self.execute(),(0,True))
 def test_self_consistent_artifact_different_caller(self):self.assertEqual(self.execute('caller')[1],False)
 def test_different_validated_source(self):self.assertEqual(self.execute('validation')[1],False)
