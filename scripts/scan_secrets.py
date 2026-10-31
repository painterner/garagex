#!/usr/bin/env python3
"""Check publishable files and optionally known private files, without printing matches."""
import argparse,json,pathlib,re,subprocess,sys,tomllib
ROOT=pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS={".runtime",".venv","venv","__pycache__"}
PATTERNS=[
 ("private-key",re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----")),
 ("github-token",re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
 ("garage-access-key",re.compile(rb"\bGK[0-9a-f]{24}\b")),
 ("legacy-host",re.compile(rb"198\.23\.175\.12")),
]
def private_values(path):
    path=pathlib.Path(path)
    if not path.exists():return []
    if path.suffix==".json":data=json.loads(path.read_text())
    elif path.suffix==".toml":data=tomllib.loads(path.read_text())
    else:return [path.read_text().strip().encode()]
    found=[]
    def walk(value,name=""):
        if isinstance(value,dict):
            for key,item in value.items():walk(item,key)
        elif isinstance(value,list):
            for item in value:walk(item,name)
        elif isinstance(value,str) and any(word in name.lower() for word in ["secret","token","access_key","accesskey"]):
            if len(value)>=12:found.append(value.encode())
    walk(data);return found
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--secret-file",action="append",default=[]);parser.add_argument("--history",action="store_true");args=parser.parse_args()
    names=subprocess.check_output(["git","ls-files","-z","--cached","--others","--exclude-standard"],cwd=ROOT).decode().split("\0")
    known=[value for path in args.secret_file for value in private_values(path) if value]
    failures=[]
    def inspect(name,data):
        parts=pathlib.PurePosixPath(name).parts
        if FORBIDDEN_PARTS.intersection(parts):failures.append((name,"runtime-path"))
        for label,pattern in PATTERNS:
            if pattern.search(data):failures.append((name,label))
        if any(value in data for value in known):failures.append((name,"known-private-value"))
    for name in sorted(set(filter(None,names))):
        path=ROOT/name
        if path.is_symlink():failures.append((name,"symlink"));continue
        if path.is_file():inspect(name,path.read_bytes())
    # Check staged blob contents as well as working files: a later edit must not
    # hide a secret already staged in the Git index.
    staged=subprocess.check_output(["git","ls-files","--stage","-z"],cwd=ROOT).decode().split(chr(0))
    for row in filter(None,staged):
        metadata,name=row.split(chr(9),1);mode,oid,stage=metadata.split()
        if mode=="120000":failures.append(("index:"+name,"symlink"));continue
        inspect("index:"+name,subprocess.check_output(["git","cat-file","blob",oid],cwd=ROOT))
    if args.history:
        rows=subprocess.check_output(["git","rev-list","--objects","--all"],cwd=ROOT).decode().splitlines()
        for row in rows:
            oid,_,name=row.partition(" ")
            kind=subprocess.check_output(["git","cat-file","-t",oid],cwd=ROOT).strip()
            if kind==b"blob":inspect("history:"+name,subprocess.check_output(["git","cat-file","blob",oid],cwd=ROOT))
    if failures:
        for name,label in failures:print("FAIL "+name+" ["+label+"]")
        raise SystemExit(1)
    print("PASS: no matching private credentials, tokens, private keys or legacy host in publishable files.")
if __name__=="__main__":main()
