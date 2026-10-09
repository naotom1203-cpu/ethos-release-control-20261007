import json,sys
from pathlib import Path
from assemble_build_receipt import assemble
from controller_contract import signing_identity,validate_native_source

def main():
    source,result,output,identity,destination,expected,validation=sys.argv[1:]
    actual=json.loads(Path(source).read_text())
    independent=json.loads(Path(expected).read_text())
    if actual!=independent:raise ValueError("caller_source_contract_mismatch")
    validated=validate_native_source(independent)
    if json.loads(Path(validation).read_text()).get("source")!=validated:raise ValueError("source_validation_mismatch")
    i=json.loads(Path(identity).read_text())
    if i.get('callerRepository')!='ethos-security-recovery/ethos-recovery' or i.get('issuer')!='https://token.actions.githubusercontent.com' or i.get('identity')!=signing_identity(i['owner'],i['repository'],i['workflowSha']):raise ValueError('signer_identity_binding_invalid')
    document=assemble(actual,json.loads(Path(result).read_text()),Path(output),i['owner'],i['repository'],i['workflowSha'])
    Path(destination).write_text(json.dumps(document,sort_keys=True,separators=(',',':'))+'\n')

if __name__=="__main__":main()
