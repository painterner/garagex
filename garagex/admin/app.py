"""S3 key management: existing master S3 SigV4 login, scoped Garage management."""
import argparse,asyncio,hashlib,json,logging,pathlib,re,time,uuid
import aiohttp
from aiohttp import web
import sys
from garagex.auth import verify_signature,SignatureError

ROOT=pathlib.Path(__file__).parent
LOG=logging.getLogger("s3_admin")
STATE=web.AppKey("state",object)

class AdminError(Exception):
    def __init__(self,status,code,message):
        self.status=status;self.code=code;self.message=message

class Garage:
    def __init__(self,url,token):self.url=url;self.token=token;self.session=None
    async def start(self):
        self.session=aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
    async def close(self):await self.session.close()
    async def call(self,action,payload=None,query=None):
        try:
            async with self.session.request("POST" if payload is not None else "GET",self.url+"/v2/"+action,
                params=query,json=payload,headers={"Authorization":"Bearer "+self.token},allow_redirects=False) as response:
                if response.status!=200:
                    raise AdminError(502,"garage_error","存储管理操作失败，请刷新列表后检查结果。")
                return await response.json()
        except (aiohttp.ClientError,asyncio.TimeoutError):
            raise AdminError(502,"garage_unavailable","暂时无法连接存储管理服务。")

class State:
    def __init__(self,config,garage):
        self.config=config;self.garage=garage;self.failures={};self.created={};self.created_buckets={};self.create_lock=asyncio.Lock()
    def client_ip(self,request):
        forwarded=request.headers.get("X-Forwarded-For","") if request.remote in {"127.0.0.1","::1"} else ""
        return forwarded.rsplit(",",1)[-1].strip() or request.remote or "unknown"
    def auth(self,request,body):
        origin=request.headers.get("Origin")
        if (origin and origin!=self.config["origin"]) or request.headers.get("Sec-Fetch-Site")=="cross-site":
            raise AdminError(403,"origin_rejected","请从管理页面所在的域名调用。")
        ident=self.client_ip(request);now=time.monotonic()
        self.failures={key:[v for v in rows if v>now-60] for key,rows in self.failures.items() if rows and rows[-1]>now-60}
        if len(self.failures.get(ident,[]))>=20:
            raise AdminError(429,"login_rate_limited","认证失败次数过多，请一分钟后重试。")
        try:verify_signature(request.method,request.raw_path,request.headers,body,self.config["credentials"])
        except SignatureError:
            if len(self.failures)<4096 or ident in self.failures:self.failures.setdefault(ident,[]).append(now)
            raise AdminError(401,"unauthorized","请使用现有主 S3 Access Key 和 Secret Key 登录，并检查系统时间。")
        request["principal"]={"role":"platform","tenant_id":None,"key_id":self.config["credentials"]["access_key_id"]}
        request["s3_credentials"]=self.config["credentials"]
    def public_key(self,key):
        # Explicit allowlist: ordinary responses must never contain secret material.
        return {k:key.get(k) for k in ["accessKeyId","name","created","expiration","expired","permissions","buckets"]}|{
            "isAdmin":key.get("accessKeyId")==self.config["credentials"]["access_key_id"]}
    async def session(self,request):
        return web.json_response({"endpoint":self.config["origin"],"region":self.config["credentials"]["region"],
            "defaultBucket":self.config["credentials"]["bucket"],"adminKeyId":self.config["credentials"]["access_key_id"]})
    async def keys(self,request):
        offset=request.query.get("offset")
        if offset is not None and not re.fullmatch(r"GK[0-9a-f]{24}",offset):
            raise AdminError(400,"invalid_cursor","无效的分页位置。")
        query={"limit":"31"}
        if offset:query["offset"]=offset
        rows=await self.garage.call("ListKeys",query=query)
        semaphore=asyncio.Semaphore(5)
        async def detail(row):
            async with semaphore:
                return self.public_key(await self.garage.call("GetKeyInfo",query={"id":row["id"]}))
        items=await asyncio.gather(*(detail(row) for row in rows[:30]))
        return web.json_response({"items":items,"nextCursor":rows[30]["id"] if len(rows)>30 else None})
    def public_bucket(self,row):
        return {"id":row["id"],"aliases":row.get("globalAliases",[]),"created":row.get("created"),
            "objects":row.get("objects",0),"bytes":row.get("bytes",0),
            "unfinishedUploads":row.get("unfinishedUploads",0),
            "unfinishedMultipartUploads":row.get("unfinishedMultipartUploads",0),
            "quotas":row.get("quotas",{}),
            "keys":[{"accessKeyId":key["accessKeyId"],"name":key.get("name",""),
                "permissions":{name:bool(key.get("permissions",{}).get(name)) for name in ["read","write","owner"]},
                "isAdmin":key["accessKeyId"]==self.config["credentials"]["access_key_id"]} for key in row.get("keys",[])]}
    async def buckets(self,request):
        rows=await self.garage.call("ListBuckets")
        semaphore=asyncio.Semaphore(5)
        async def detail(row):
            async with semaphore:
                return self.public_bucket(await self.garage.call("GetBucketInfo",query={"id":row["id"]}))
        return web.json_response({"items":await asyncio.gather(*(detail(row) for row in rows))})
    async def create_bucket(self,request):
        try:data=await request.json()
        except ValueError:raise AdminError(400,"invalid_json","请提供 JSON 请求。")
        if not isinstance(data,dict) or set(data)!={"name","request_id"}:
            raise AdminError(400,"invalid_request","请提供桶名称和请求 ID。")
        name=data["name"];ident=data["request_id"]
        if not isinstance(name,str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]",name):
            raise AdminError(400,"invalid_bucket_name","桶名称须为 3～63 个小写字母、数字或短横线，且以字母或数字开头、结尾。")
        try:
            if not isinstance(ident,str) or uuid.UUID(ident).version!=4:raise ValueError()
        except (ValueError,AttributeError):
            raise AdminError(400,"invalid_request_id","请使用 UUID v4 请求 ID。")
        fingerprint=hashlib.sha256(await request.read()).hexdigest()
        async with self.create_lock:
            cutoff=time.monotonic()-600
            self.created_buckets={key:value for key,value in self.created_buckets.items() if value[0]>cutoff}
            if ident in self.created_buckets:
                _,old_fingerprint,result=self.created_buckets[ident]
                if old_fingerprint!=fingerprint:raise AdminError(409,"request_id_conflict","该请求 ID 已用于另一组参数。")
                return web.json_response(result,status=201)
            existing=await self.garage.call("ListBuckets")
            if any(name in row.get("globalAliases",[]) for row in existing):
                raise AdminError(409,"bucket_exists","同名存储桶已存在，请使用其他名称。")
            # Garage supports aliases and initial key permissions in one create operation.
            # Giving the master key read/write avoids creating an unusable bucket.
            created=await self.garage.call("CreateBucket",{"globalAlias":name,"localAlias":{
                "accessKeyId":self.config["credentials"]["access_key_id"],"alias":name,
                "allow":{"read":True,"write":True,"owner":False}}})
            result={"bucket":self.public_bucket(created)}
            while len(self.created_buckets)>=128:self.created_buckets.pop(next(iter(self.created_buckets)))
            self.created_buckets[ident]=(time.monotonic(),fingerprint,result)
            LOG.info("admin_bucket_created bucket_id=%s",created["id"])
            return web.json_response(result,status=201)
    def key_id(self,request):
        ident=request.match_info["id"]
        if not re.fullmatch(r"GK[0-9a-f]{24}",ident):raise AdminError(400,"invalid_key","无效的 Access Key ID。")
        return ident
    async def reveal(self,request):
        ident=self.key_id(request)
        row=await self.garage.call("GetKeyInfo",query={"id":ident,"showSecretKey":"true"})
        if not row.get("secretAccessKey"):raise AdminError(404,"secret_unavailable","该密钥已不可用。")
        LOG.info("admin_secret_revealed key_id=%s",ident)
        return web.json_response({"accessKeyId":ident,"secretAccessKey":row["secretAccessKey"]})
    async def create(self,request):
        try:data=await request.json()
        except ValueError:raise AdminError(400,"invalid_json","请提供 JSON 请求。")
        if not isinstance(data,dict) or set(data)!={"name","grants","request_id"}:
            raise AdminError(400,"invalid_request","请提供名称、桶权限和请求 ID。")
        name=data["name"];grants=data["grants"];ident=data["request_id"]
        if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(c)<32 or ord(c)==127 for c in name):
            raise AdminError(400,"invalid_name","名称须为 1～80 个字符，不能包含控制字符。")
        try:
            if not isinstance(ident,str) or uuid.UUID(ident).version!=4:raise ValueError()
        except (ValueError,AttributeError):
            raise AdminError(400,"invalid_request_id","请使用 UUID v4 请求 ID。")
        if not isinstance(grants,list) or not 1<=len(grants)<=100:
            raise AdminError(400,"invalid_permissions","请至少选择一个桶的读或写权限。")
        seen=set()
        for grant in grants:
            if (not isinstance(grant,dict) or set(grant)!={"bucketId","read","write"}
                or not isinstance(grant["bucketId"],str) or not re.fullmatch(r"[0-9a-f]{64}",grant["bucketId"])
                or type(grant["read"]) is not bool or type(grant["write"]) is not bool
                or not (grant["read"] or grant["write"]) or grant["bucketId"] in seen):
                raise AdminError(400,"invalid_permissions","桶权限格式无效或重复。")
            seen.add(grant["bucketId"])
        fingerprint=hashlib.sha256(await request.read()).hexdigest()
        async with self.create_lock:
            cutoff=time.monotonic()-600
            self.created={key:value for key,value in self.created.items() if value[0]>cutoff}
            if ident in self.created:
                _,old_fingerprint,result=self.created[ident]
                if old_fingerprint!=fingerprint:raise AdminError(409,"request_id_conflict","该请求 ID 已用于另一组参数。")
                return web.json_response(result,status=201)
            buckets=await self.garage.call("ListBuckets")
            if not seen.issubset({b["id"] for b in buckets}):
                raise AdminError(400,"bucket_not_found","所选桶不存在，请刷新后重试。")
            created=await self.garage.call("CreateKey",{"name":name.strip(),"deny":{"createBucket":True},"neverExpires":True})
            key_id=created["accessKeyId"]
            try:
                for grant in grants:
                    await self.garage.call("AllowBucketKey",{"bucketId":grant["bucketId"],"accessKeyId":key_id,
                        "permissions":{"read":grant["read"],"write":grant["write"],"owner":False}})
                full=await self.garage.call("GetKeyInfo",query={"id":key_id})
            except (Exception,asyncio.CancelledError):
                try:await asyncio.shield(self.garage.call("DeleteKey",{},query={"id":key_id}))
                except Exception:LOG.error("admin_create_rollback_failed key_id=%s",key_id)
                raise
            result={"key":self.public_key(full),"secretAccessKey":created["secretAccessKey"]}
            while len(self.created)>=128:self.created.pop(next(iter(self.created)))
            self.created[ident]=(time.monotonic(),fingerprint,result)
            LOG.info("admin_key_created key_id=%s",key_id)
            return web.json_response(result,status=201)

@web.middleware
async def boundary(request,handler):
    try:
        if request.path.startswith("/admin/api/"):
            body=await request.read()
            result=request.app[STATE].auth(request,body)
            if hasattr(result,"__await__"):await result
        response=await handler(request)
    except AdminError as error:
        response=web.json_response({"error":{"code":error.code,"message":error.message}},status=error.status)
        if error.status==401:response.headers["WWW-Authenticate"]="AWS4-HMAC-SHA256"
    except web.HTTPException as error:response=error
    except Exception:
        LOG.error("admin_request_failed")
        response=web.json_response({"error":{"code":"internal_error","message":"管理服务发生错误，请刷新列表检查结果。"}},status=500)
    response.headers.update({"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY",
        "Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"})
    return response

def make_app(config,garage=None,object_client_factory=None):
    garage=garage or Garage(config["garage_url"],config["garage_token"])
    app=web.Application(middlewares=[boundary],client_max_size=32768)
    if config.get("tenant_db"):
        from .tenancy import tenant_state
        state=tenant_state(State,AdminError)(config,garage)
    else:state=State(config,garage)
    app[STATE]=state
    from .objects import Objects
    state.objects=Objects(state,AdminError,object_client_factory);state.objects.attach(app)
    app.router.add_get("/admin/api/session",state.session)
    app.router.add_get("/admin/api/keys",state.keys)
    app.router.add_post("/admin/api/keys",state.create)
    app.router.add_get("/admin/api/buckets",state.buckets)
    app.router.add_post("/admin/api/buckets",state.create_bucket)
    app.router.add_post("/admin/api/keys/{id}/reveal",state.reveal)
    if hasattr(state,"attach"):state.attach(app)
    assets={"/admin/":("index.html","text/html"),"/admin/style.css":("style.css","text/css"),
            "/admin/app.js":("app.js","text/javascript"),"/admin/sigv4.mjs":("sigv4.mjs","text/javascript")}
    async def asset(request):
        filename,content_type=assets[request.path]
        return web.Response(body=(ROOT/"static"/filename).read_bytes(),content_type=content_type)
    for path in assets:app.router.add_get(path,asset)
    async def lifecycle(app):
        await garage.start()
        try:
            if hasattr(state,"registry"):await state.registry.call("initialize")
            yield
        finally:
            await state.objects.close()
            await garage.close()
    app.cleanup_ctx.append(lifecycle)
    return app

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--config",default="/etc/garagex/admin.json")
    config=json.loads(pathlib.Path(parser.parse_args().config).read_text())
    config["credentials"]=json.loads(pathlib.Path(config["credentials_file"]).read_text())
    config["garage_token"]=pathlib.Path(config["garage_token_file"]).read_text().strip()
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    web.run_app(make_app(config),host=config.get("host","127.0.0.1"),port=config["port"],access_log=None)
if __name__=="__main__":main()
