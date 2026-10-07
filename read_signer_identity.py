"""Request only signer identity metadata; never save or print the OIDC token."""
import base64,json,os,re,urllib.request,urllib.parse
from controller_contract import signing_identity

def validate_claims(claims):
    prefix='naotom1203-cpu/ethos-release-control-20261007/.github/workflows/protected-build.yml@'
    ref=claims.get('job_workflow_ref','');sha=claims.get('job_workflow_sha','')
    if claims.get('iss')!='https://token.actions.githubusercontent.com' or claims.get('aud')!='sigstore':raise ValueError('issuer_audience_mismatch')
    if claims.get('repository')!='naotom1203-cpu/ethos-recovery':raise ValueError('private_caller_repository_mismatch')
    if ref!=prefix+sha or not re.fullmatch('[a-f0-9]{40}',sha):raise ValueError('immutable_signer_workflow_required')
    return {'owner':'naotom1203-cpu','repository':'ethos-release-control-20261007','workflowSha':sha,'identity':signing_identity('naotom1203-cpu','ethos-release-control-20261007',sha),'issuer':claims['iss'],'callerRepository':claims['repository']}

if __name__=='__main__':
    url=os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'];parsed=urllib.parse.urlparse(url)
    if parsed.scheme!='https' or not (parsed.hostname or '').endswith('.actions.githubusercontent.com'):raise ValueError('oidc_request_endpoint_invalid')
    url+=('&' if parsed.query else '?')+'audience=sigstore'
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    with urllib.request.urlopen(request,timeout=15) as response:document=json.loads(response.read(100000))
    token=document.pop('value');segments=token.split('.')
    if len(segments)!=3:raise ValueError('oidc_token_shape_invalid')
    claims=json.loads(base64.urlsafe_b64decode(segments[1]+'='*(-len(segments[1])%4)))
    metadata=validate_claims(claims);token=None;claims.clear()
    print(json.dumps(metadata))
