"""Generic protected-build checks. No provider credentials or product values."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlparse

HEX40 = re.compile(r'^[a-f0-9]{40}$')
HEX64 = re.compile(r'^[a-f0-9]{64}$')


def validate_native_source(document):
    for field in ('originalCommit', 'sourceTree', 'snapshotCommit'):
        if not isinstance(document.get(field), str) or not HEX40.fullmatch(document[field]):
            raise ValueError('source_identity_invalid')
    if not HEX64.fullmatch(str(document.get('packageLockSha256',''))):
        raise ValueError('source_lockfile_identity_missing')
    try:
        raw = base64.b64decode(document['originalCommitObjectBase64'], validate=True)
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError('native_commit_encoding_invalid') from exc
    if len(raw) > 20000 or b'\0' in raw:
        raise ValueError('native_commit_size_invalid')
    digest = hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if digest != document['originalCommit']:
        raise ValueError('native_commit_identity_mismatch')
    if hashlib.sha256(raw).hexdigest() != document.get('originalCommitObjectSha256'):
        raise ValueError('native_commit_content_mismatch')
    header = raw.split(b'\n\n', 1)[0].splitlines()
    trees = [line for line in header if line.startswith(b'tree ')]
    if trees != [b'tree '+document['sourceTree'].encode()]:
        raise ValueError('native_commit_tree_mismatch')
    return {'originalCommit':document['originalCommit'], 'sourceTree':document['sourceTree'],
            'snapshotCommit':document['snapshotCommit'], 'packageLockSha256':document['packageLockSha256'], 'nativeCommitObjectVerified':True}


def verify_lockfile(lock, source_root):
    if lock.get('lockfileVersion') != 3 or not isinstance(lock.get('packages'),dict):
        raise ValueError('lockfile_shape_invalid')
    components = []
    for path, package in sorted(lock['packages'].items()):
        if not path:
            continue
        if not isinstance(package,dict):
            raise ValueError('locked_package_shape_invalid')
        resolved = package.get('resolved')
        if resolved:
            if not isinstance(resolved,str):
                raise ValueError('resolved_package_location_invalid')
            parsed = urlparse(resolved)
            if parsed.scheme:
                if (parsed.scheme != 'https' or parsed.hostname != 'registry.npmjs.org' or
                        parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None,443)):
                    raise ValueError('unapproved_package_registry')
                if not re.fullmatch(r'sha512-[A-Za-z0-9+/]+={0,2}',str(package.get('integrity',''))):
                    raise ValueError('registry_integrity_missing')
            else:
                relative = PurePosixPath(resolved)
                if relative.is_absolute() or '..' in relative.parts or not resolved.startswith('vendor/'):
                    raise ValueError('unapproved_local_package')
                target = source_root.joinpath(*relative.parts)
                if not target.is_dir() or target.is_symlink() or not target.resolve().is_relative_to(source_root.resolve()):
                    raise ValueError('local_package_boundary_invalid')
        components.append({'path':path,'version':package.get('version'), 'resolved':resolved,
                           'integrity':package.get('integrity')})
    if not components:
        raise ValueError('locked_component_inventory_empty')
    return {'lockedComponentCount':len(components),
            'lockfileSha256':hashlib.sha256(json.dumps(lock,sort_keys=True,separators=(',',':')).encode()).hexdigest()}


def artifact_manifest(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('build_output_boundary_invalid')
    files=[]
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('build_output_symlink_rejected')
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError('build_output_special_or_hardlink_rejected')
        relative=path.relative_to(root).as_posix()
        if any(part.startswith('.env') for part in PurePosixPath(relative).parts):
            raise ValueError('build_output_environment_file_rejected')
        if path.stat().st_size > 100_000_000 or len(files) >= 100_000:
            raise ValueError('build_output_resource_limit_exceeded')
        data=path.read_bytes()
        files.append({'path':relative,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    if not files:
        raise ValueError('build_output_empty')
    manifest=json.dumps(files,sort_keys=True,separators=(',',':')).encode()
    return {'files':files,'fileManifestSha256':hashlib.sha256(manifest).hexdigest()}


def signing_identity(owner, controller_repo, workflow_commit):
    if not re.fullmatch(r'[A-Za-z0-9_-]+',owner) or not re.fullmatch(r'[A-Za-z0-9_.-]+',controller_repo):
        raise ValueError('signer_repository_invalid')
    if not HEX40.fullmatch(workflow_commit):
        raise ValueError('signer_must_use_immutable_commit')
    return 'https://github.com/'+owner+'/'+controller_repo+'/.github/workflows/protected-build.yml@'+workflow_commit


def verify_signed_receipt_shape(receipt, expected_source, actual_manifest, expected_signer):
    source=validate_native_source(expected_source)
    if (receipt.get('schema')!='ethos-protected-build/v1' or
            receipt.get('source')!=source or receipt.get('artifactManifest')!=actual_manifest or
            receipt.get('signerIdentity')!=expected_signer or
            receipt.get('signingIssuer')!='https://token.actions.githubusercontent.com' or
            receipt.get('sourceBuildSandbox')!='no-network-no-credentials-non-root' or
            receipt.get('typecheckPassed') is not True or receipt.get('buildPassed') is not True):
        raise ValueError('signed_build_receipt_boundary_mismatch')
    # This is only the content gate. Cosign cryptographic bundle verification,
    # immutable signer identity and actual branch-protection readback are required.
    return {'status':'RECEIPT_CONTENT_VERIFIED_ONLY','cryptographicSignatureVerified':False}


def verify_branch_protection(document, required_checks):
    checks=document.get('required_status_checks') or {}
    actual=set(checks.get('contexts') or [])
    actual.update(x.get('context') for x in checks.get('checks',[]) if isinstance(x,dict))
    if (not required_checks or not set(required_checks).issubset(actual) or checks.get('strict') is not True or
        (document.get('enforce_admins') or {}).get('enabled') is not True or
        (document.get('allow_force_pushes') or {}).get('enabled') is not False or
        (document.get('allow_deletions') or {}).get('enabled') is not False or
        not document.get('required_pull_request_reviews')):
        raise ValueError('native_branch_protection_incomplete')
    return {'status':'NATIVE_PROTECTION_CONFIGURATION_VERIFIED','requiredChecks':sorted(required_checks),'forcePushAllowed':False,'deletionAllowed':False,'adminsEnforced':True}
