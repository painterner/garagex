#!/usr/bin/env python3
"""Generate private local configuration without copying any deployment's credentials."""
import argparse,ipaddress,json,os,pathlib,re,secrets,socket,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
def atomic(path,value,mode=0o640,gid=10001):
    path=pathlib.Path(path);tmp=path.with_name(path.name+".new")
    tmp.write_text(value);tmp.chmod(mode)
    if os.geteuid()==0:os.chown(tmp,0,gid)
    tmp.replace(path)
def configure(domain,email,bucket,runtime=None):
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?",domain) or ".." in domain:
        raise ValueError("Use a DNS hostname without a scheme, path or port.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+",email):raise ValueError("Provide an ACME account email.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]",bucket):raise ValueError("Invalid initial bucket name.")
    runtime=pathlib.Path(runtime) if runtime else ROOT/".runtime"
    manifest=runtime/"installation.json"
    settings={"domain":domain,"email":email,"bucket":bucket}
    if manifest.exists() and json.loads(manifest.read_text())!=settings:
        raise RuntimeError("This runtime directory belongs to different settings. No files were replaced.")
    runtime.mkdir(mode=0o700,parents=True,exist_ok=True)
    for relative,uid,gid,mode in [
        ("garage",0,10002,0o750),("config",0,10001,0o750),("secrets",0,10001,0o750),
        ("secrets/admin",0,10001,0o750),("secrets/proxy",0,10001,0o750),
        ("data",10002,10002,0o750),("meta",10002,10002,0o750),
        ("jobs",10001,10001,0o750),("tenants",10001,10001,0o750),
        ("docs",0,0,0o755),("caddy-data",0,0,0o700),("caddy-config",0,0,0o700)]:
        path=runtime/relative;path.mkdir(parents=True,exist_ok=True);path.chmod(mode)
        if os.geteuid()==0:os.chown(path,uid,gid)
    credentials_file=runtime/"secrets/credentials.json"
    if not credentials_file.exists():
        credentials={"access_key_id":"GK"+secrets.token_hex(12),"secret_access_key":secrets.token_hex(32),
            "region":"garage","bucket":bucket,"endpoint":"https://"+domain,"proxy_endpoint":"https://"+domain+"/_proxy/download"}
        atomic(credentials_file,json.dumps(credentials,indent=2)+"\n")
    credentials=json.loads(credentials_file.read_text())
    garage_token=runtime/"garage/admin-token"
    if not garage_token.exists():atomic(garage_token,secrets.token_urlsafe(48)+"\n",0o600,10002)
    garage_token.chmod(0o600)
    if os.geteuid()==0:os.chown(garage_token,10002,10002)
    garage_toml=runtime/"garage/garage.toml"
    if not garage_toml.exists():
        atomic(garage_toml,f"""metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
metadata_fsync = true
data_fsync = true
rpc_bind_addr = "[::]:3901"
rpc_public_addr = "garage:3901"
rpc_secret = "{secrets.token_hex(32)}"

[s3_api]
s3_region = "garage"
api_bind_addr = "[::]:3900"
root_domain = ".{domain}"
public_endpoint = "https://{domain}"
public_endpoint_path_style = true

[admin]
api_bind_addr = "[::]:3903"
admin_token_file = "/run/garage-admin-token"
""",gid=10002)
    env="GARAGE_DEFAULT_ACCESS_KEY="+credentials["access_key_id"]+"\nGARAGE_DEFAULT_SECRET_KEY="+credentials["secret_access_key"]+"\nGARAGE_DEFAULT_BUCKET="+bucket+"\n"
    atomic(runtime/"garage.env",env,0o600,0)
    blocked=set()
    for family,_,_,_,address in socket.getaddrinfo(socket.gethostname(),None):
        try:blocked.add(str(ipaddress.ip_address(address[0])))
        except ValueError:pass
    try:
        for _,_,_,_,address in socket.getaddrinfo(domain,443):blocked.add(str(ipaddress.ip_address(address[0])))
    except socket.gaierror:pass
    proxy=dict(host="0.0.0.0",port=3910,s3_endpoint="http://garage:3900",bucket=bucket,
        tenant_db="/var/lib/garagex/tenants/registry.sqlite3",garage_url="http://garage:3903",garage_token_file="/run/secrets/service-token",
        credentials_file="/etc/garagex/credentials.json",state_dir="/var/lib/garagex/jobs",key_prefix="proxy/",
        max_concurrent=4,max_bytes=50*1024**3,part_size=8*1024**2,total_timeout=21600,source_idle_timeout=60,
        client_write_timeout=120,continue_on_disconnect=True,retention_seconds=7*86400,
        download_retention_seconds=None,cleanup_interval_seconds=5,network_max_bytes=512*1024**2,
        network_max_concurrent=2,blocked_ips=sorted(blocked))
    admin=dict(host="0.0.0.0",port=3911,origin="https://"+domain,garage_url="http://garage:3903",
        credentials_file="/etc/garagex/credentials.json",garage_token_file="/run/secrets/service-token",
        tenant_db="/var/lib/garagex/tenants/registry.sqlite3",s3_endpoint="http://garage:3900")
    atomic(runtime/"config/proxy.json",json.dumps(proxy,indent=2)+"\n")
    atomic(runtime/"config/admin.json",json.dumps(admin,indent=2)+"\n")
    caddy=f"""{{
    email {email}
}}
{domain} {{
    redir /docs /docs/ 308
    handle_path /docs/* {{
        root * /srv/docs
        header {{
            X-Content-Type-Options nosniff
            Cache-Control no-cache
            Content-Security-Policy "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        }}
        file_server
    }}
    redir /admin /admin/ 308
    handle /admin/* {{
        reverse_proxy admin:3911
    }}
    handle /_proxy/* {{
        reverse_proxy proxy:3910 {{
            flush_interval 100ms
        }}
    }}
    handle {{
        header Content-Security-Policy "sandbox"
        reverse_proxy garage:3900
    }}
}}
"""
    atomic(runtime/"config/Caddyfile",caddy,0o644,0)
    for source in (ROOT/"docs").rglob("*"):
        if not source.is_file():continue
        relative=source.relative_to(ROOT/"docs");target=runtime/"docs"/relative;target.parent.mkdir(parents=True,exist_ok=True)
        text=source.read_text().replace("s3.example.com",domain)
        if source.suffix in {".html",".json",".py"}:text=text.replace('"garagex"','"'+bucket+'"').replace("s3://garagex/","s3://"+bucket+"/")
        atomic(target,text,0o644,0)
        target.parent.chmod(0o755)
    atomic(manifest,json.dumps(settings,indent=2)+"\n",0o600,0)
    print("Configuration ready. Real credentials were generated locally; no secret values were printed.")
    print("Admin URL: https://"+domain+"/admin/")
    print("Credentials file: "+str(credentials_file))
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--domain",required=True);parser.add_argument("--email",required=True);parser.add_argument("--bucket",default="garagex")
    args=parser.parse_args();configure(args.domain,args.email,args.bucket)
if __name__=="__main__":main()
