"""External tenants: native per-tenant S3 keys plus server-side resource ownership."""
import asyncio,hashlib,json,re,time,uuid
from aiohttp import web
from garagex.auth import verify_signature,SignatureError
from garagex.tenants import Registry,TenantError,request_key

def tenant_state(base,Error):
    class TenantState(base):
        def __init__(self,config,garage):
            super().__init__(config,garage);self.registry=Registry(config["tenant_db"]);self.provisioned={}
        def principal(self,request):return request["principal"]
        def platform(self,request):
            if self.principal(request)["role"]!="platform":raise Error(403,"platform_only","此操作仅限平台主管理员。")
        async def db(self,method,*args,**kwargs):
            try:return await self.registry.call(method,*args,**kwargs)
            except TenantError as error:raise Error(error.status,error.code,error.message)
        async def auth(self,request,body):
            if request_key(request.headers)==self.config["credentials"]["access_key_id"]:
                return super().auth(request,body)
            origin=request.headers.get("Origin")
            if (origin and origin!=self.config["origin"]) or request.headers.get("Sec-Fetch-Site")=="cross-site":
                raise Error(403,"origin_rejected","请从控制台所在域名调用。")
            ident=self.client_ip(request);now=time.monotonic()
            self.failures={key:[value for value in values if value>now-60] for key,values in self.failures.items() if values and values[-1]>now-60}
            if len(self.failures.get(ident,[]))>=20:raise Error(429,"login_rate_limited","认证失败次数过多，请一分钟后重试。")
            key=request_key(request.headers);record=await self.db("key",key) if key else None
            try:
                if not record or record["role"]!="owner" or record["tenant_status"]!="active":raise SignatureError()
                info=await self.garage.call("GetKeyInfo",query={"id":key,"showSecretKey":"true"})
                if info.get("expired") or not info.get("secretAccessKey"):raise SignatureError()
                credentials={"access_key_id":key,"secret_access_key":info["secretAccessKey"],"region":self.config["credentials"]["region"]}
                verify_signature(request.method,request.raw_path,request.headers,body,credentials)
            except (SignatureError,Error):
                if len(self.failures)<4096 or ident in self.failures:self.failures.setdefault(ident,[]).append(now)
                raise Error(401,"unauthorized","管理密钥验证失败；应用密钥不能登录租户控制台。")
            request["principal"]={"role":"tenant","tenant_id":record["tenant_id"],"key_id":key}
            request["s3_credentials"]=credentials
        async def session(self,request):
            result={"endpoint":self.config["origin"],"region":self.config["credentials"]["region"],
                "defaultBucket":self.config["credentials"]["bucket"],"role":self.principal(request)["role"]}
            if result["role"]=="platform":result["adminKeyId"]=self.config["credentials"]["access_key_id"]
            else:
                tenant=await self.db("tenant",self.principal(request)["tenant_id"])
                result["tenant"]={k:tenant[k] for k in ["id","name","prefix","quota_bytes","max_buckets","max_keys","max_concurrent"]}
                result["defaultBucket"]=""
            return web.json_response(result)
        async def resolve_bucket(self,request,ident):
            if not re.fullmatch(r"[0-9a-f]{64}",ident):raise Error(404,"bucket_not_found","没有找到该存储桶。")
            principal=self.principal(request)
            if principal["role"]=="tenant":
                owned=await self.db("bucket",ident,principal["tenant_id"])
                if not owned:raise Error(404,"bucket_not_found","没有找到该存储桶。")
            row=await self.garage.call("GetBucketInfo",query={"id":ident})
            return row
        async def buckets(self,request):
            principal=self.principal(request)
            if principal["role"]=="platform":rows=await self.garage.call("ListBuckets")
            else:rows=[{"id":row["garage_id"]} for row in await self.db("buckets",principal["tenant_id"])]
            owned_keys={row["access_key_id"]:row for row in await self.db("keys",principal["tenant_id"])} if principal["tenant_id"] else None
            semaphore=asyncio.Semaphore(5)
            async def detail(row):
                async with semaphore:
                    result=self.public_bucket(await self.resolve_bucket(request,row["id"]))
                    ownership=await self.db("bucket",row["id"])
                    if ownership:
                        result["tenantId"]=ownership["tenant_id"];result["label"]=ownership["label"]
                        result["allocatedQuotaBytes"]=ownership["quota_bytes"]
                    if owned_keys is not None:result["keys"]=[k for k in result["keys"] if k["accessKeyId"] in owned_keys]
                    return result
            return web.json_response({"items":await asyncio.gather(*(detail(row) for row in rows))})
        async def keys(self,request):
            principal=self.principal(request)
            if principal["role"]=="platform":
                response=await super().keys(request);data=json.loads(response.body)
                for row in data["items"]:
                    ownership=await self.db("key",row["accessKeyId"])
                    if ownership:row.update(tenantId=ownership["tenant_id"],tenantName=ownership["tenant_name"],role=ownership["role"])
                return web.json_response(data)
            rows=await self.db("keys",principal["tenant_id"]);items=[]
            for row in rows:
                info=self.public_key(await self.garage.call("GetKeyInfo",query={"id":row["access_key_id"]}))
                info.update(role=row["role"],tenantId=principal["tenant_id"]);items.append(info)
            return web.json_response({"items":items,"nextCursor":None})
        async def reveal(self,request):
            principal=self.principal(request);ident=self.key_id(request)
            if principal["role"]=="tenant":
                row=await self.db("key",ident)
                if not row or row["tenant_id"]!=principal["tenant_id"]:raise Error(404,"key_not_found","没有找到该密钥。")
            return await super().reveal(request)
        async def create(self,request):
            principal=self.principal(request)
            if principal["role"]=="platform":return await super().create(request)
            try:data=await request.json()
            except ValueError:raise Error(400,"invalid_json","请提供 JSON 请求。")
            if not isinstance(data,dict) or set(data)!={"name","grants","request_id"}:raise Error(400,"invalid_request","请提供名称、桶权限和请求 ID。")
            name=data["name"];grants=data["grants"];request_id=data["request_id"]
            if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(c)<32 or ord(c)==127 for c in name):raise Error(400,"invalid_name","密钥名称无效。")
            try:
                if not isinstance(request_id,str) or uuid.UUID(request_id).version!=4:raise ValueError()
            except (ValueError,AttributeError):raise Error(400,"invalid_request_id","请求 ID 无效。")
            if not isinstance(grants,list) or not 1<=len(grants)<=100:raise Error(400,"invalid_permissions","请选择存储桶读写权限。")
            seen=set()
            for grant in grants:
                if (not isinstance(grant,dict) or set(grant)!={"bucketId","read","write"} or type(grant["read"]) is not bool or type(grant["write"]) is not bool
                    or not (grant["read"] or grant["write"]) or not isinstance(grant["bucketId"],str) or grant["bucketId"] in seen):
                    raise Error(400,"invalid_permissions","桶权限格式无效。")
                if not await self.db("bucket",grant["bucketId"],principal["tenant_id"]):raise Error(404,"bucket_not_found","没有找到该存储桶。")
                seen.add(grant["bucketId"])
            fingerprint=hashlib.sha256(await request.read()).hexdigest();cache_key=principal["tenant_id"]+":"+request_id
            async with self.create_lock:
                cutoff=time.monotonic()-600;self.created={key:value for key,value in self.created.items() if value[0]>cutoff}
                if cache_key in self.created:
                    _,old,result=self.created[cache_key]
                    if old!=fingerprint:raise Error(409,"request_id_conflict","该请求 ID 已用于另一组参数。")
                    return web.json_response(result,status=201)
                reservation=await self.db("reserve_key",principal["tenant_id"])
                created=None
                try:
                    created=await self.garage.call("CreateKey",{"name":name.strip(),"deny":{"createBucket":True},"neverExpires":True})
                    ident=created["accessKeyId"]
                    for grant in grants:
                        await self.garage.call("AllowBucketKey",{"bucketId":grant["bucketId"],"accessKeyId":ident,
                            "permissions":{"read":grant["read"],"write":grant["write"],"owner":False}})
                    await self.db("finish_key",reservation,ident)
                    info=self.public_key(await self.garage.call("GetKeyInfo",query={"id":ident}));info["role"]="app"
                    result={"key":info,"secretAccessKey":created["secretAccessKey"]}
                except (Exception,asyncio.CancelledError):
                    if created:
                        try:
                            await asyncio.shield(self.garage.call("DeleteKey",{},query={"id":created["accessKeyId"]}))
                            await self.db("revoke_key",created["accessKeyId"])
                        except Exception:pass
                    await self.db("release_key",reservation);raise
                while len(self.created)>=128:self.created.pop(next(iter(self.created)))
                self.created[cache_key]=(time.monotonic(),fingerprint,result)
                await self.db("audit",principal["tenant_id"],principal["key_id"],"key.create",ident)
                return web.json_response(result,status=201)
        async def create_bucket(self,request):
            principal=self.principal(request)
            if principal["role"]=="platform":return await super().create_bucket(request)
            try:data=await request.json()
            except ValueError:raise Error(400,"invalid_json","请提供 JSON 请求。")
            if not isinstance(data,dict) or set(data)-{"name","request_id","quota_bytes"}:raise Error(400,"invalid_request","桶参数无效。")
            name=data.get("name");request_id=data.get("request_id");quota=data.get("quota_bytes",1024**3)
            if not isinstance(name,str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,46}[a-z0-9]",name):raise Error(400,"invalid_bucket_name","桶名称须为 3～48 个小写字母、数字或短横线，首尾为字母或数字。")
            if type(quota) is not int or quota<1024**2:raise Error(400,"invalid_quota","桶配额至少为 1 MiB。")
            try:
                if not isinstance(request_id,str) or uuid.UUID(request_id).version!=4:raise ValueError()
            except (ValueError,AttributeError):raise Error(400,"invalid_request_id","请求 ID 无效。")
            fingerprint=hashlib.sha256(await request.read()).hexdigest();cache_key=principal["tenant_id"]+":"+request_id
            async with self.create_lock:
                self.created_buckets={key:value for key,value in self.created_buckets.items() if value[0]>time.monotonic()-600}
                if cache_key in self.created_buckets:
                    _,old,result=self.created_buckets[cache_key]
                    if old!=fingerprint:raise Error(409,"request_id_conflict","该请求 ID 已用于另一组参数。")
                    return web.json_response(result,status=201)
                reservation=await self.db("reserve_bucket",principal["tenant_id"],name,quota);created=None
                try:
                    created=await self.garage.call("CreateBucket",{"globalAlias":reservation["name"]})
                    ident=created["id"]
                    await self.garage.call("UpdateBucket",{"quotas":{"maxSize":quota,"maxObjects":None}},query={"id":ident})
                    owners=[row["access_key_id"] for row in await self.db("keys",principal["tenant_id"]) if row["role"]=="owner"]
                    for key in [self.config["credentials"]["access_key_id"],*owners]:
                        await self.garage.call("AllowBucketKey",{"bucketId":ident,"accessKeyId":key,
                            "permissions":{"read":True,"write":True,"owner":False}})
                    await self.db("finish_bucket",reservation["id"],ident)
                    row=await self.garage.call("GetBucketInfo",query={"id":ident});result={"bucket":self.public_bucket(row)}
                    result["bucket"].update(label=name,tenantId=principal["tenant_id"],allocatedQuotaBytes=quota)
                    owned={row["access_key_id"] for row in await self.db("keys",principal["tenant_id"])}
                    result["bucket"]["keys"]=[k for k in result["bucket"]["keys"] if k["accessKeyId"] in owned]
                except (Exception,asyncio.CancelledError):
                    # If creation timed out without an ID, keep the reservation for operator reconciliation.
                    cleaned=False
                    if created:
                        try:
                            await asyncio.shield(self.garage.call("DeleteBucket",{},query={"id":created["id"]}));cleaned=True
                        except Exception:pass
                    await self.db("fail_bucket",reservation["id"],created["id"] if created else None,cleaned=cleaned);raise
                while len(self.created_buckets)>=128:self.created_buckets.pop(next(iter(self.created_buckets)))
                self.created_buckets[cache_key]=(time.monotonic(),fingerprint,result)
                await self.db("audit",principal["tenant_id"],principal["key_id"],"bucket.create",ident)
                return web.json_response(result,status=201)
        async def list_tenants(self,request):
            self.platform(request);rows=await self.db("tenants")
            for row in rows:row["allocated_bytes"]=await self.db("allocated",row["id"])
            return web.json_response({"items":rows})
        async def create_tenant(self,request):
            self.platform(request)
            try:data=await request.json()
            except ValueError:raise Error(400,"invalid_json","请提供 JSON 请求。")
            if not isinstance(data,dict) or set(data)-{"name","quota_bytes","max_buckets","max_keys","max_concurrent","request_id"}:raise Error(400,"invalid_request","租户参数无效。")
            name=data.get("name");request_id=data.get("request_id")
            if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(c)<32 or ord(c)==127 for c in name):raise Error(400,"invalid_name","租户名称无效。")
            values=[data.get("quota_bytes",10*1024**3),data.get("max_buckets",10),data.get("max_keys",10),data.get("max_concurrent",2)]
            for value,minimum,maximum in zip(values,[1024**2,1,2,1],[10*1024**4,100,100,4]):
                if type(value) is not int or not minimum<=value<=maximum:raise Error(400,"invalid_limit","租户配额或数量限制无效。")
            try:
                if not isinstance(request_id,str) or uuid.UUID(request_id).version!=4:raise ValueError()
            except (ValueError,AttributeError):raise Error(400,"invalid_request_id","请求 ID 无效。")
            fingerprint=hashlib.sha256(await request.read()).hexdigest()
            async with self.create_lock:
                self.provisioned={key:value for key,value in self.provisioned.items() if value[0]>time.monotonic()-600}
                if request_id in self.provisioned:
                    _,old,result=self.provisioned[request_id]
                    if old!=fingerprint:raise Error(409,"request_id_conflict","该请求 ID 已用于另一组参数。")
                    return web.json_response(result,status=201)
                tenant=await self.db("create_tenant",name.strip(),*values);created=None
                try:
                    reservation=await self.db("reserve_key",tenant["id"],"owner")
                    created=await self.garage.call("CreateKey",{"name":name.strip()+" / owner","deny":{"createBucket":True},"neverExpires":True})
                    await self.db("finish_key",reservation,created["accessKeyId"]);await self.db("activate_tenant",tenant["id"])
                except (Exception,asyncio.CancelledError):
                    if created:
                        try:await asyncio.shield(self.garage.call("DeleteKey",{},query={"id":created["accessKeyId"]}))
                        except Exception:pass
                    await self.db("discard_tenant",tenant["id"]);raise
                tenant["status"]="active"
                result={"tenant":tenant,"credentials":{"access_key_id":created["accessKeyId"],"secret_access_key":created["secretAccessKey"],
                    "endpoint":self.config["origin"],"region":self.config["credentials"]["region"]}}
                while len(self.provisioned)>=64:self.provisioned.pop(next(iter(self.provisioned)))
                self.provisioned[request_id]=(time.monotonic(),fingerprint,result)
                await self.db("audit",tenant["id"],self.principal(request)["key_id"],"tenant.create",tenant["id"])
                return web.json_response(result,status=201)
        async def usage(self,request):
            principal=self.principal(request)
            if principal["role"]!="tenant":raise Error(403,"tenant_only","请使用客户管理密钥查看租户用量。")
            tenant=await self.db("tenant",principal["tenant_id"]);bucket_data=json.loads((await self.buckets(request)).body)["items"]
            return web.json_response({"tenant":tenant,"allocated_bytes":await self.db("allocated",tenant["id"]),
                "used_bytes":sum(b["bytes"] for b in bucket_data),"objects":sum(b["objects"] for b in bucket_data),
                "bucket_count":len(bucket_data),"key_count":len(await self.db("keys",tenant["id"]))})
        async def revoke(self,request):
            principal=self.principal(request);ident=self.key_id(request);record=await self.db("key",ident)
            if ident==self.config["credentials"]["access_key_id"] or not record:raise Error(404,"key_not_found","没有找到可撤销的应用密钥。")
            if principal["role"]=="tenant" and record["tenant_id"]!=principal["tenant_id"]:raise Error(404,"key_not_found","没有找到该密钥。")
            if record["role"]=="owner":raise Error(409,"owner_key_protected","管理密钥受保护；可由平台暂停租户。")
            await self.garage.call("DeleteKey",{},query={"id":ident});await self.db("revoke_key",ident)
            await self.db("audit",record["tenant_id"],principal["key_id"],"key.revoke",ident)
            return web.json_response({"revoked":True})
        async def set_status(self,request):
            self.platform(request);ident=request.match_info["id"]
            tenant=await self.db("tenant",ident)
            try:data=await request.json()
            except ValueError:raise Error(400,"invalid_json","请提供 JSON 请求。")
            status=data.get("status") if isinstance(data,dict) else None
            if status not in {"active","suspended"}:raise Error(400,"invalid_status","状态必须为 active 或 suspended。")
            await self.db("set_status",ident,"suspending" if status=="suspended" else "resuming")
            for row in await self.db("keys",ident):
                payload={"expiration":"1970-01-01T00:00:00Z"} if status=="suspended" else {"neverExpires":True}
                await self.garage.call("UpdateKey",payload,query={"id":row["access_key_id"]})
            await self.db("set_status",ident,status)
            await self.db("audit",ident,self.principal(request)["key_id"],"tenant."+status,ident)
            return web.json_response({"status":status})
        async def audit_log(self,request):
            return web.json_response({"items":await self.db("audits",self.principal(request)["tenant_id"])})
        def attach(self,app):
            app.router.add_get("/admin/api/tenants",self.list_tenants)
            app.router.add_post("/admin/api/tenants",self.create_tenant)
            app.router.add_post("/admin/api/tenants/{id}/status",self.set_status)
            app.router.add_get("/admin/api/usage",self.usage)
            app.router.add_get("/admin/api/audit",self.audit_log)
            app.router.add_post("/admin/api/keys/{id}/revoke",self.revoke)
    return TenantState
