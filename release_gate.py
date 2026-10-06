"""Trusted-controller decision core. No publishing or credentials in this module.
Deployment may be performed only by a separate controller with isolated identity.
"""
import hashlib,hmac,json,re
from pathlib import Path

def signed_payload(record):
 return json.dumps({k:v for k,v in record.items() if k != "signature"},sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def decide(record,artifact,required_checks,policy_sha,*,attestation_key):
 errors=[]
 if record.get('policySha256')!=policy_sha:errors.append('untrusted policy')
 if not re.fullmatch('[0-9a-f]{40}',record.get('sourceCommit','')):errors.append('invalid source revision')
 if record.get('testedCommit')!=record.get('sourceCommit'):errors.append('revision mismatch')
 if not isinstance(attestation_key,bytes) or len(attestation_key)<32:
  errors.append('trusted key unavailable')
 else:
  expected=hmac.new(attestation_key,signed_payload(record),hashlib.sha256).hexdigest()
  if not isinstance(record.get('signature'),str) or not hmac.compare_digest(expected,record['signature']):errors.append('invalid controller signature')
 if record.get('checks')!={name:'PASS' for name in required_checks}:errors.append('required check absent or failed')
 if record.get('artifactSha256')!=hashlib.sha256(Path(artifact).read_bytes()).hexdigest():errors.append('artifact mismatch')
 return {'allowPublication':not errors,'reasons':errors,'sourceCommit':record.get('sourceCommit'),'artifactSha256':record.get('artifactSha256')}
# Attestation authenticity must be established by the isolated service, not a
# developer-provided JSON boolean. This core is not the credential boundary.
