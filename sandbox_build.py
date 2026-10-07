"""Root-prepared generic build sandbox; requires an isolated Linux CI runner."""
import hashlib,json,os,shutil,subprocess,sys,tempfile
from contextlib import contextmanager
from pathlib import Path
from controller_contract import artifact_manifest
IMAGE='node@sha256:c4d5523090a817b7aa86d2111241fdd4f66d1e27782b44160e6aa63b357ecb2d'

@contextmanager
def disposable_directory():
    # Only a freshly controller-created directory is removed.
    tmp = Path(tempfile.mkdtemp(prefix='protected-build-'))
    try:
        yield str(tmp)
    except BaseException as primary:
        try:
            shutil.rmtree(tmp)
        except BaseException as cleanup:
            raise BaseExceptionGroup('Build and temporary directory cleanup failed', [primary, cleanup]) from None
        raise
    else:
        shutil.rmtree(tmp)

def run(args, capture=False):
    return subprocess.run(args,check=True,timeout=1200,capture_output=capture,env={'PATH':os.environ['PATH'],'HOME':os.environ.get('HOME','/tmp')})

def build(source,output):
    source=source.resolve();output=output.resolve()
    if output.exists():raise ValueError('output_must_be_new')
    for file in source.rglob('*'):
        if file.is_symlink():raise ValueError('source_symlink_not_admitted')
        if (file.name.startswith('.env') and file.name!='.env.example') or file.name=='.npmrc':raise ValueError('source_credentials_configuration_rejected')
    scripts=json.loads((source/'package.json').read_text()).get('scripts',{})
    expected_prebuild='node scripts/verify-mandatory-security-build-gates.mjs && node scripts/normalize-vinext-font-cache.mjs && node scripts/verify-migration-versions.mjs && node scripts/write-release-manifest.mjs'
    if scripts.get('prebuild')!=expected_prebuild or scripts.get('build')!='WRANGLER_LOG_PATH=.wrangler/wrangler.log vinext build':
        raise ValueError('reviewed_build_lifecycle_changed')
    with disposable_directory() as tmp:
        work=Path(tmp)/'work';shutil.copytree(source,work)
        # This directory is disposable and contains only the reviewed source.
        try:
            run(['docker','run','--rm','--network','none','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','FOWNER','--security-opt','no-new-privileges','--mount','type=bind,src='+str(work)+',dst=/work',IMAGE,'chown','-R','1000:1000','/work'])
            base=['docker','run','--rm','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--pids-limit','256','--memory','6g','--cpus','2','--tmpfs','/tmp:rw,nosuid,size=1g,uid=1000,gid=1000','--mount','type=bind,src='+str(work)+',dst=/work','--workdir','/work','--env','HOME=/tmp','--env','CI=true']
            run(base+['--network','bridge',IMAGE,'npm','ci','--ignore-scripts','--no-audit','--no-fund','--registry=https://registry.npmjs.org'])
            original_lock_hash=hashlib.sha256((work/'package-lock.json').read_bytes()).hexdigest()
            audit=run(base+['--network','bridge',IMAGE,'npm','audit','--ignore-scripts','--json','--audit-level=high','--registry=https://registry.npmjs.org'],capture=True)
            if len(audit.stdout)>10_000_000:raise ValueError('audit_response_too_large')
            vulnerability_counts=json.loads(audit.stdout).get('metadata',{}).get('vulnerabilities')
            if not isinstance(vulnerability_counts,dict) or any(vulnerability_counts.get(k)!=0 for k in ['info','low','moderate','high','critical','total']):
                raise ValueError('known_dependency_vulnerability_or_unknown_audit')
            trusted=Path(tmp)/'trusted';(trusted/'bin').mkdir(parents=True)
            (trusted/'audit.json').write_bytes(audit.stdout)
            shim=trusted/'bin'/'npm'
            shim.write_text('#!/bin/sh\nif [ "$#" -eq 2 ] && [ "$1" = audit ] && [ "$2" = --json ]; then cat /trusted/audit.json; exit 0; fi\nif [ "$1" = audit ]; then echo "Unreviewed audit invocation" >&2; exit 1; fi\nexec /usr/local/bin/npm "$@"\n')
            shim.chmod(0o755)
            (trusted/'npm-gate-cli.mjs').write_text("import fs from 'node:fs';import {spawnSync} from 'node:child_process';const args=process.argv.slice(2);if(JSON.stringify(args)===JSON.stringify(['audit','--audit-level=high'])){const v=JSON.parse(fs.readFileSync('/trusted/audit.json','utf8')).metadata?.vulnerabilities;if(!v||['info','low','moderate','high','critical','total'].some(k=>v[k]!==0))process.exit(1);console.log(JSON.stringify({freshRegistryAuditSnapshotValidated:true,vulnerabilities:v}));}else if(JSON.stringify(args)===JSON.stringify(['run','verify:security'])){const r=spawnSync(process.execPath,['/usr/local/lib/node_modules/npm/bin/npm-cli.js',...args],{stdio:'inherit',env:process.env});if(r.error||r.signal)process.exit(1);process.exit(r.status??1);}else{process.exit(1);}")
            offline=base+['--mount','type=bind,src='+str(trusted)+',dst=/trusted,readonly','--env','PATH=/trusted/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']
            # The baseline's exact npm audit --json call consumes this immutable
            # fresh registry response; all other npm calls use the official CLI.
            # The original prebuild runs npm audit, which requires registry access.
            # Its security source gate and every other reviewed prebuild step run below;
            # the audit is performed above with scripts disabled and no credentials.
            # Product code receives no network, secrets, OIDC token, host socket or controller mount.
            run(offline+['--network','none',IMAGE,'sh','-eu','-c','npm run typecheck && npm_execpath=/trusted/npm-gate-cli.mjs node scripts/verify-mandatory-security-build-gates.mjs && node scripts/normalize-vinext-font-cache.mjs && node scripts/verify-migration-versions.mjs && node scripts/write-release-manifest.mjs && npm run build --ignore-scripts && npm run verify:release:manifest'])
            if hashlib.sha256((work/'package-lock.json').read_bytes()).hexdigest()!=original_lock_hash:raise ValueError('lockfile_changed_after_registry_audit')
            built=work/'dist';manifest=artifact_manifest(built)
            shutil.copytree(built,output)
            if artifact_manifest(output)!=manifest:raise ValueError('copied_artifact_mismatch')
            return {'artifactManifest':manifest,'typecheckPassed':True,'buildPassed':True,'sourceBuildSandbox':'no-network-no-credentials-non-root','image':IMAGE,'registryAuditVulnerabilities':vulnerability_counts,'allReviewedPrebuildChecksExecuted':True,'auditedLockfileSha256':original_lock_hash,'registryAuditResponseSha256':hashlib.sha256(audit.stdout).hexdigest()}
        finally:
            primary = sys.exc_info()[1]
            try:
                run(['docker','run','--rm','--network','none','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','FOWNER','--security-opt','no-new-privileges','--mount','type=bind,src='+str(work)+',dst=/work',IMAGE,'chown','-R',str(os.getuid())+':'+str(os.getgid()),'/work'])
            except Exception as cleanup_error:
                if primary is not None:
                    raise ExceptionGroup('Build and disposable cleanup failed', [primary, cleanup_error]) from None
                raise


if __name__=='__main__':
    result=build(Path(sys.argv[1]),Path(sys.argv[2]));Path(sys.argv[3]).write_text(json.dumps(result,sort_keys=True)+'\n')
