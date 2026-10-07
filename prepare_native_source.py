"""Restore authenticated native commit identity in an isolated CI checkout only."""
import base64,hashlib,json,subprocess,sys
from pathlib import Path
from controller_contract import validate_native_source,verify_lockfile

def git(root,*args,input=None):
    return subprocess.run(['git','-c','core.hooksPath=/dev/null','-C',str(root),*args],input=input,capture_output=True,check=True).stdout.decode().strip()

def prepare(root,document):
    source=validate_native_source(document)
    root=root.resolve()
    if not (root/'.git').is_dir() or (root/'.git').is_symlink():raise ValueError('isolated_checkout_required')
    if git(root,'rev-parse','HEAD')!=source['snapshotCommit']:raise ValueError('snapshot_commit_mismatch')
    if git(root,'rev-parse','HEAD^{tree}')!=source['sourceTree']:raise ValueError('snapshot_tree_mismatch')
    if git(root,'status','--porcelain','--untracked-files=all'):raise ValueError('source_checkout_dirty')
    if any(root.glob('.npmrc')):raise ValueError('project_npm_configuration_rejected')
    if hashlib.sha256((root/'package-lock.json').read_bytes()).hexdigest()!=source['packageLockSha256']:raise ValueError('source_lockfile_hash_mismatch')
    lock=verify_lockfile(json.loads((root/'package-lock.json').read_text()),root)
    raw=base64.b64decode(document['originalCommitObjectBase64'],validate=True)
    stored=git(root,'hash-object','-w','-t','commit','--stdin',input=raw)
    if stored!=source['originalCommit']:raise ValueError('native_commit_store_mismatch')
    git(root,'update-ref','--no-deref','HEAD',stored)
    (root/'.git'/'shallow').write_text(stored+'\n')
    if git(root,'rev-parse','HEAD^{tree}')!=source['sourceTree']:raise ValueError('native_tree_after_store_mismatch')
    if git(root,'status','--porcelain','--untracked-files=all'):raise ValueError('source_changed_during_identity_restore')
    return {'source':source,'lock':lock,'productFilesChanged':False}

if __name__=='__main__':
    print(json.dumps(prepare(Path(sys.argv[1]),json.loads(Path(sys.argv[2]).read_text()))))
