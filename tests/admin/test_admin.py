import copy,json,unittest,uuid
from aiohttp.test_utils import AioHTTPTestCase
from garagex.admin.app import make_app,STATE,AdminError
from garagex.auth import signed_request

MASTER={"access_key_id":"GK"+"a"*24,"secret_access_key":"b"*64,"region":"garage","bucket":"painterner"}
BUCKET="c"*64
class FakeGarage:
    def __init__(self):
        self.keys={};self.calls=[];self.fail_allow=False
        self.bucket_rows={BUCKET:{"id":BUCKET,"globalAliases":["painterner"],"created":"2026-10-30T00:00:00Z",
            "objects":3,"bytes":2048,"keys":[],"quotas":{"maxSize":None,"maxObjects":None}}}
    async def start(self):pass
    async def close(self):pass
    async def call(self,action,payload=None,query=None):
        self.calls.append(action);query=query or {}
        if action=="ListBuckets":return [{"id":row["id"],"globalAliases":row["globalAliases"]} for row in self.bucket_rows.values()]
        if action=="GetBucketInfo":return copy.deepcopy(self.bucket_rows[query["id"]])
        if action=="CreateBucket":
            ident=uuid.uuid4().hex+uuid.uuid4().hex;alias=payload["globalAlias"];local=payload["localAlias"]
            key={"accessKeyId":local["accessKeyId"],"name":self.keys[local["accessKeyId"]]["name"],"permissions":local["allow"]}
            self.bucket_rows[ident]={"id":ident,"globalAliases":[alias],"created":"2026-10-31T00:00:00Z","objects":0,"bytes":0,
                "keys":[key],"quotas":{"maxSize":None,"maxObjects":None}}
            self.keys[local["accessKeyId"]]["buckets"].append({"id":ident,"globalAliases":[alias],"permissions":local["allow"]})
            return copy.deepcopy(self.bucket_rows[ident])
        if action=="ListKeys":
            rows=sorted(self.keys);offset=query.get("offset","")
            return [{"id":k,"name":self.keys[k]["name"]} for k in rows if k>=offset][:int(query.get("limit",100))]
        if action=="CreateKey":
            ident="GK"+uuid.uuid4().hex[:24]
            row={"accessKeyId":ident,"name":payload["name"],"secretAccessKey":"d"*64,"created":"2026-10-30T00:00:00Z","expiration":None,"expired":False,"permissions":{"createBucket":False},"buckets":[]}
            self.keys[ident]=row
            return copy.deepcopy(row)
        if action=="GetKeyInfo":
            if query["id"] not in self.keys:raise AdminError(404,"not_found","not found")
            row=copy.deepcopy(self.keys[query["id"]])
            if query.get("showSecretKey")!="true":row.pop("secretAccessKey",None)
            return row
        if action=="AllowBucketKey":
            if self.fail_allow:raise AdminError(502,"garage_error","failed")
            self.keys[payload["accessKeyId"]]["buckets"].append({"id":BUCKET,"globalAliases":["painterner"],"permissions":payload["permissions"]})
            return {}
        if action=="DeleteKey":self.keys.pop(query["id"],None);return {}
        raise AssertionError(action)

class AdminTests(AioHTTPTestCase):
    async def get_application(self):
        self.garage=FakeGarage()
        self.garage.keys[MASTER["access_key_id"]]={"accessKeyId":MASTER["access_key_id"],"name":"primary","secretAccessKey":MASTER["secret_access_key"],"created":None,"expiration":None,"expired":False,"permissions":{"createBucket":False},"buckets":[]}
        return make_app({"credentials":MASTER,"origin":"https://s3.example.com"},self.garage)
    async def request(self,path,method="GET",payload=None,credentials=None,extra=None):
        body=json.dumps(payload).encode() if payload is not None else None
        url=str(self.server.make_url("/admin/api"+path))
        signed=signed_request(credentials or MASTER,url,data=body,method=method)
        headers=dict(signed.header_items())
        if payload is not None:headers["Content-Type"]="application/json"
        if extra:headers.update(extra)
        return await self.client.session.request(method,url,data=body,headers=headers)
    def creation(self):
        return {"name":"test application","request_id":str(uuid.uuid4()),"grants":[{"bucketId":BUCKET,"read":True,"write":False}]}
    async def test_anonymous_assets_and_authenticated_api(self):
        for path,mime in [("/admin/","text/html"),("/admin/app.js","text/javascript"),("/admin/style.css","text/css"),("/admin/sigv4.mjs","text/javascript")]:
            r=await self.client.get(path);self.assertEqual(r.status,200);self.assertEqual(r.content_type,mime)
            self.assertEqual(r.headers["Cache-Control"],"no-store")
        r=await self.client.get("/admin/api/keys");self.assertEqual(r.status,401)
        self.assertEqual(self.garage.calls,[])
        r=await self.request("/session");self.assertEqual(r.status,200)
    async def test_other_s3_keys_cannot_administer(self):
        ordinary={**MASTER,"access_key_id":"GK"+"e"*24}
        r=await self.request("/keys",credentials=ordinary);self.assertEqual(r.status,401)
        self.assertFalse(self.garage.calls)
    async def test_list_never_exposes_secrets(self):
        r=await self.request("/keys");data=await r.json()
        self.assertNotIn("secretAccessKey",json.dumps(data))
        self.assertTrue(data["items"][0]["isAdmin"])
    async def test_secret_requires_explicit_signed_reveal(self):
        r=await self.request("/keys/"+MASTER["access_key_id"]+"/reveal",method="POST",payload={})
        self.assertEqual((await r.json())["secretAccessKey"],MASTER["secret_access_key"])
    async def test_create_and_idempotency(self):
        body=self.creation()
        r=await self.request("/keys",method="POST",payload=body);self.assertEqual(r.status,201);created=await r.json()
        self.assertFalse(created["key"]["permissions"]["createBucket"])
        self.assertEqual(created["key"]["buckets"][0]["permissions"],{"read":True,"write":False,"owner":False})
        r=await self.request("/keys",method="POST",payload=body);self.assertEqual((await r.json()),created)
        self.assertEqual(self.garage.calls.count("CreateKey"),1)
        body["name"]="changed";r=await self.request("/keys",method="POST",payload=body);self.assertEqual(r.status,409)
    async def test_failed_grant_rolls_back_new_key(self):
        self.garage.fail_allow=True
        r=await self.request("/keys",method="POST",payload=self.creation());self.assertEqual(r.status,502)
        self.assertEqual(len(self.garage.keys),1)
        self.assertEqual(self.garage.calls[-1],"DeleteKey")
    async def test_cannot_create_owner_or_unknown_bucket(self):
        body=self.creation();body["grants"][0]["owner"]=True
        r=await self.request("/keys",method="POST",payload=body);self.assertEqual(r.status,400)
        body=self.creation();body["grants"][0]["bucketId"]="f"*64
        r=await self.request("/keys",method="POST",payload=body);self.assertEqual(r.status,400)
        self.assertNotIn("CreateKey",self.garage.calls)
    async def test_origin_rejected(self):
        r=await self.request("/keys",extra={"Origin":"https://attacker.invalid"});self.assertEqual(r.status,403)
        self.assertFalse(self.garage.calls)
    async def test_invalid_signature_rate_limited(self):
        for _ in range(20):
            r=await self.client.get("/admin/api/session");self.assertEqual(r.status,401)
        r=await self.request("/session");self.assertEqual(r.status,429)
    async def test_buckets_include_usage_and_sanitize_key_metadata(self):
        self.garage.bucket_rows[BUCKET]["keys"]=[{"accessKeyId":MASTER["access_key_id"],"name":"primary",
            "permissions":{"read":True,"write":True},"secretAccessKey":"should never return"}]
        r=await self.request("/buckets");self.assertEqual(r.status,200);body=await r.json()
        self.assertEqual(body["items"][0]["objects"],3)
        self.assertEqual(body["items"][0]["bytes"],2048)
        self.assertNotIn("secretAccessKey",json.dumps(body))
    async def test_create_bucket_grants_master_and_is_idempotent(self):
        data={"name":"app-backups","request_id":str(uuid.uuid4())}
        r=await self.request("/buckets",method="POST",payload=data);self.assertEqual(r.status,201);created=await r.json()
        self.assertEqual(created["bucket"]["aliases"],["app-backups"])
        self.assertTrue(created["bucket"]["keys"][0]["isAdmin"])
        self.assertEqual(created["bucket"]["keys"][0]["permissions"],{"read":True,"write":True,"owner":False})
        r=await self.request("/buckets",method="POST",payload=data);self.assertEqual(await r.json(),created)
        self.assertEqual(self.garage.calls.count("CreateBucket"),1)
        data["name"]="another-bucket"
        r=await self.request("/buckets",method="POST",payload=data);self.assertEqual(r.status,409)
    async def test_duplicate_bucket_does_not_change_existing_bucket(self):
        r=await self.request("/buckets",method="POST",payload={"name":"painterner","request_id":str(uuid.uuid4())})
        self.assertEqual(r.status,409);self.assertNotIn("CreateBucket",self.garage.calls)
    async def test_invalid_bucket_names_rejected_before_creating(self):
        for name in ["ab","a"*64,"Uppercase","with.dot","-prefix","suffix-","含中文"," has-space",False]:
            r=await self.request("/buckets",method="POST",payload={"name":name,"request_id":str(uuid.uuid4())})
            self.assertEqual(r.status,400)
        self.assertNotIn("CreateBucket",self.garage.calls)
    async def test_ordinary_keys_cannot_create_buckets(self):
        ordinary={**MASTER,"access_key_id":"GK"+"e"*24}
        r=await self.request("/buckets",method="POST",payload={"name":"app-backups","request_id":str(uuid.uuid4())},credentials=ordinary)
        self.assertEqual(r.status,401);self.assertFalse(self.garage.calls)
    async def test_pagination_does_not_skip_keys(self):
        for index in range(34):
            ident="GK"+f"{index:024x}"
            self.garage.keys[ident]={**self.garage.keys[MASTER["access_key_id"]],"accessKeyId":ident,"name":str(index)}
        r=await self.request("/keys");first=await r.json();self.assertEqual(len(first["items"]),30)
        r=await self.request("/keys?offset="+first["nextCursor"]);second=await r.json()
        ids=[key["accessKeyId"] for key in first["items"]+second["items"]]
        self.assertEqual(len(ids),len(set(ids)));self.assertEqual(len(ids),35)
if __name__=="__main__":unittest.main(verbosity=2)
