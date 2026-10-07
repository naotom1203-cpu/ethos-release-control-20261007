import json,sys
from pathlib import Path
from assemble_build_receipt import assemble
from controller_contract import signing_identity
source,result,output,identity,destination=sys.argv[1:]
i=json.loads(Path(identity).read_text())
if i.get('callerRepository')!='naotom1203-cpu/ethos-recovery' or i.get('issuer')!='https://token.actions.githubusercontent.com' or i.get('identity')!=signing_identity(i['owner'],i['repository'],i['workflowSha']):raise ValueError('signer_identity_binding_invalid')
document=assemble(json.loads(Path(source).read_text()),json.loads(Path(result).read_text()),Path(output),i['owner'],i['repository'],i['workflowSha'])
Path(destination).write_text(json.dumps(document,sort_keys=True,separators=(',',':'))+'\n')
