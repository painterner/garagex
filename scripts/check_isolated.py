#!/usr/bin/env python3
"""Disposable real-stack verification; no existing deployment directories are modified."""
import json,os,pathlib,shutil,socket,subprocess,tempfile,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    subprocess.run(['ss','-lntup'],check=True)
    for port in [13900,13910,13911]:
        with socket.socket() as sock:
            try:sock.bind(('127.0.0.1',port))
            except OSError:raise SystemExit('Test port '+str(port)+' is occupied; nothing changed.')
    project='garagex-check-'+uuid.uuid4().hex[:10]
    image=project+':local';env={**os.environ,'GARAGEX_IMAGE':image}
    names=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=ROOT).decode().split(chr(0))
    with tempfile.TemporaryDirectory(prefix='garagex-check-') as directory:
        work=pathlib.Path(directory)
        for name in filter(None,names):
            source=ROOT/name
            if not source.is_file():continue
            if any(part in {'.runtime','.venv','node_modules','__pycache__'} for part in source.relative_to(ROOT).parts):continue
            target=work/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
        compose=['docker','compose','-p',project,'-f','compose.yaml','-f','deploy/compose.test.yaml']
        def run(args):subprocess.run(args,cwd=work,env=env,check=True)
        try:
            run(['python3','scripts/configure.py','--domain','s3.integration.invalid','--email','admin@example.invalid','--bucket','garagex'])
            run(compose+['up','-d','--build','init','admin','proxy'])
            mount=['run','--rm','--no-deps','-T','-v',str(work)+':/checks:ro','-w','/checks']
            run(compose+mount+['-e','TEST_REAL_S3=1','-e','GARAGEX_CREDENTIALS=/run/bootstrap/output/credentials.json','-e','GARAGEX_S3_ENDPOINT=http://garage:3900','init','python','-m','unittest','discover','-s','tests','-t','.','-q'])
            run(compose+mount+['init','python','scripts/verify_tenants.py','--credentials','/run/bootstrap/output/credentials.json','--s3','http://garage:3900','--admin','http://admin:3911','--proxy','http://proxy:3910','--garage-admin','http://garage:3903','--garage-token','/run/bootstrap/master-token'])
            run(compose+['run','--rm','--no-deps','-T','caddy','caddy','validate','--config','/etc/caddy/Caddyfile'])
            print('PASS: disposable real S3, tenant/proxy isolation and Caddy configuration.')
        finally:
            subprocess.run(compose+['down','--remove-orphans'],cwd=work,env=env,check=False)
            subprocess.run(['docker','image','rm',image],check=False)
if __name__=='__main__':main()
