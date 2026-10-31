"""Idempotent creation of limited internal service tokens; never prints secrets."""
import json,os,pathlib,time,urllib.error,urllib.request

SCOPES={
 "admin":["ListKeys","GetKeyInfo","CreateKey","DeleteKey","ListBuckets","GetBucketInfo","CreateBucket","AllowBucketKey","UpdateBucket","DeleteBucket","UpdateKey"],
 "proxy":["GetKeyInfo"],
}
def main():
    root=pathlib.Path("/run/bootstrap/output")
    token=pathlib.Path("/run/bootstrap/master-token").read_text().strip()
    base="http://garage:3903/v2/"
    def call(action,payload=None,query=""):
        data=json.dumps(payload).encode() if payload is not None else None
        request=urllib.request.Request(base+action+query,data=data,
            headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
        with urllib.request.urlopen(request,timeout=10) as response:return json.load(response)
    for _ in range(90):
        try:call("ListBuckets");break
        except (OSError,urllib.error.URLError):time.sleep(1)
    else:raise RuntimeError("Garage did not become ready.")
    for service,scope in SCOPES.items():
        path=root/service/"service-token"
        if path.exists():
            token_id=path.read_text().strip().split(".",1)[0]
            current=call("GetAdminTokenInfo",query="?id="+token_id)
            if current.get("name")!="garagex-"+service:raise RuntimeError("Unexpected service token identity.")
            if set(current.get("scope",[]))!=set(scope):call("UpdateAdminToken",{"scope":scope},"?id="+token_id)
        else:
            result=call("CreateAdminToken",{"name":"garagex-"+service,"scope":scope,"neverExpires":True})
            tmp=path.with_suffix(".new");tmp.write_text(result["secretToken"]+"\n")
            tmp.chmod(0o640);os.chown(tmp,0,10001);tmp.replace(path)
        print("Internal "+service+" service token ready.",flush=True)
    print("GarageX bootstrap complete. Credentials remain in the private runtime directory.",flush=True)
if __name__=="__main__":main()
