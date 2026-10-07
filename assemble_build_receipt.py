import json,sys
from pathlib import Path
from controller_contract import validate_native_source,artifact_manifest,signing_identity
from sandbox_build import IMAGE

def assemble(source_document,result,output,owner,repo,workflow_sha):
    source=validate_native_source(source_document)
    if result.get('image')!=IMAGE:raise ValueError('build_image_not_reviewed')
    manifest=artifact_manifest(output)
    if result.get('artifactManifest')!=manifest or result.get('buildPassed') is not True or result.get('typecheckPassed') is not True or result.get('sourceBuildSandbox')!='no-network-no-credentials-non-root':
        raise ValueError('actual_build_result_mismatch')
    counts=result.get('registryAuditVulnerabilities')
    if not isinstance(counts,dict) or any(counts.get(k)!=0 for k in ['info','low','moderate','high','critical','total']) or result.get('allReviewedPrebuildChecksExecuted') is not True or result.get('auditedLockfileSha256')!=source['packageLockSha256']:
        raise ValueError('registry_audit_binding_missing')
    return {'schema':'ethos-protected-build/v1','source':source,'artifactManifest':manifest,'signerIdentity':signing_identity(owner,repo,workflow_sha),'signingIssuer':'https://token.actions.githubusercontent.com','sourceBuildSandbox':result['sourceBuildSandbox'],'typecheckPassed':True,'buildPassed':True,'image':result['image'],'registryAuditVulnerabilities':counts,'auditedLockfileSha256':result['auditedLockfileSha256'],'registryAuditResponseSha256':result['registryAuditResponseSha256'],'allReviewedPrebuildChecksExecuted':True}

if __name__=='__main__':
    source,result,output,owner,repo,workflow_sha,destination=sys.argv[1:]
    document=assemble(json.loads(Path(source).read_text()),json.loads(Path(result).read_text()),Path(output),owner,repo,workflow_sha)
    Path(destination).write_text(json.dumps(document,sort_keys=True,separators=(',',':'))+'\n')
