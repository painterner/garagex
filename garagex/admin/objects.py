"""Bounded object browsing and streaming downloads using the caller's S3 credentials."""
import asyncio,collections,contextlib,json,pathlib,re,secrets,time,urllib.parse
import boto3
from botocore.client import Config
from botocore.exceptions import BotoCoreError,ClientError
from aiohttp import web

RASTER={"image/png","image/jpeg","image/gif","image/webp","image/avif"}
RASTER_EXT={".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".gif":"image/gif",".webp":"image/webp",".avif":"image/avif"}
class Objects:
    def __init__(self,state,Error,client_factory=None):
        self.state=state;self.Error=Error;self.clients=collections.OrderedDict();self.tickets={};self.slots=asyncio.Semaphore(4)
        self.factory=client_factory
    def client(self,credentials):
        ident=credentials["access_key_id"];secret=credentials["secret_access_key"]
        cache=(ident,secret)
        if cache in self.clients:
            self.clients.move_to_end(cache);return self.clients[cache]
        if self.factory:client=self.factory(credentials)
        else:
            options={"signature_version":"s3v4","s3":{"addressing_style":"path"},"connect_timeout":10,"read_timeout":60,
                "retries":{"max_attempts":2},"max_pool_connections":4}
            for field in ["request_checksum_calculation","response_checksum_validation"]:
                if field in Config.OPTION_DEFAULTS:options[field]="when_required"
            client=boto3.client("s3",endpoint_url=self.state.config.get("s3_endpoint","http://127.0.0.1:3900"),
                region_name=credentials["region"],aws_access_key_id=ident,aws_secret_access_key=secret,config=Config(**options))
        self.clients[cache]=client
        while len(self.clients)>4:
            _,old=self.clients.popitem(last=False)
            if hasattr(old,"close"):old.close()
        return client
    async def close(self):
        for client in self.clients.values():
            if hasattr(client,"close"):client.close()
        self.clients.clear();self.tickets.clear()
    async def call(self,client,method,**kwargs):
        try:return await asyncio.to_thread(getattr(client,method),**kwargs)
        except ClientError as error:
            status=error.response.get("ResponseMetadata",{}).get("HTTPStatusCode",502)
            if status==403:raise self.Error(403,"object_access_denied","当前密钥没有该存储桶或对象的读取权限。")
            if status==404:raise self.Error(404,"object_not_found","没有找到该对象。")
            if status==412:raise self.Error(409,"object_changed","对象内容已变化，请刷新后重试。")
            if status==416:raise self.Error(416,"invalid_range","下载范围无效。")
            raise self.Error(502,"s3_unavailable","对象存储暂时无法完成请求。")
        except BotoCoreError:raise self.Error(502,"s3_unavailable","暂时无法连接对象存储。")
    def key(self,value,empty=False):
        try:valid=isinstance(value,str) and (empty or bool(value)) and len(value.encode("utf-8"))<=1024
        except UnicodeError:valid=False
        if not valid:raise self.Error(400,"invalid_object_key","对象 Key 或前缀格式无效。")
        return value
    async def bucket(self,request,ident):
        if not isinstance(ident,str) or not re.fullmatch(r"[0-9a-f]{64}",ident):
            raise self.Error(404,"bucket_not_found","没有找到该存储桶。")
        if hasattr(self.state,"resolve_bucket"):info=await self.state.resolve_bucket(request,ident)
        else:info=await self.state.garage.call("GetBucketInfo",query={"id":ident})
        aliases=info.get("globalAliases",[])
        if not aliases:
            caller=request["principal"]["key_id"]
            aliases=[alias for key in info.get("keys",[]) if key["accessKeyId"]==caller for alias in key.get("bucketLocalAliases",[])]
        if not aliases:raise self.Error(403,"bucket_alias_unavailable","该桶没有当前密钥可使用的 S3 别名。")
        return {"id":info["id"],"name":aliases[0]}
    async def listing(self,request):
        allowed={"bucket_id","prefix","mode","cursor","limit"}
        if set(request.query)-allowed:raise self.Error(400,"invalid_request","对象列表参数无效。")
        bucket=await self.bucket(request,request.query.get("bucket_id"));prefix=self.key(request.query.get("prefix",""),True)
        mode=request.query.get("mode","tree")
        try:limit=int(request.query.get("limit","100"))
        except ValueError:raise self.Error(400,"invalid_limit","每页数量无效。")
        if mode not in {"tree","flat"} or not 1<=limit<=200:raise self.Error(400,"invalid_request","列表模式或每页数量无效。")
        cursor=request.query.get("cursor")
        if cursor is not None and (not cursor or len(cursor)>8192):raise self.Error(400,"invalid_cursor","分页游标无效。")
        params={"Bucket":bucket["name"],"Prefix":prefix,"MaxKeys":limit,"EncodingType":"url"}
        if mode=="tree":params["Delimiter"]="/"
        if cursor:params["ContinuationToken"]=cursor
        result=await self.call(self.client(request["s3_credentials"]),"list_objects_v2",**params)
        decoded=lambda value:urllib.parse.unquote(value) if result.get("EncodingType")=="url" else value
        items=[{"key":decoded(row["Key"]),"size":row["Size"],"etag":row.get("ETag"),
                "lastModified":row["LastModified"].isoformat() if row.get("LastModified") else None} for row in result.get("Contents",[])]
        directories=[decoded(row["Prefix"]) for row in result.get("CommonPrefixes",[])]
        return web.json_response({"bucket":bucket,"prefix":prefix,"mode":mode,"items":items,"directories":directories,
            "nextCursor":result.get("NextContinuationToken") if result.get("IsTruncated") else None})
    async def head(self,request,bucket_id=None,key=None):
        bucket=await self.bucket(request,bucket_id if bucket_id is not None else request.query.get("bucket_id"))
        key=self.key(key if key is not None else request.query.get("key"))
        info=await self.call(self.client(request["s3_credentials"]),"head_object",Bucket=bucket["name"],Key=key)
        mime=info.get("ContentType","application/octet-stream").split(";",1)[0].lower()
        if mime=="application/octet-stream":mime=RASTER_EXT.get(pathlib.PurePosixPath(key).suffix.lower(),mime)
        return bucket,key,info,mime
    async def detail(self,request):
        bucket,key,info,mime=await self.head(request)
        return web.json_response({"bucket":bucket,"key":key,"size":info["ContentLength"],"contentType":info.get("ContentType"),
            "contentEncoding":info.get("ContentEncoding"),"etag":info.get("ETag"),
            "lastModified":info["LastModified"].isoformat() if info.get("LastModified") else None,
            "metadata":info.get("Metadata",{}),"imagePreview":mime in RASTER and info["ContentLength"]<=10*1024**2 and not info.get("ContentEncoding"),
            "textPreview":self.is_text(key,mime) and not info.get("ContentEncoding")})
    def is_text(self,key,mime):
        return mime.startswith("text/") or mime in {"application/json","application/xml","application/yaml","application/toml","image/svg+xml"} or pathlib.PurePosixPath(key).suffix.lower() in {".txt",".json",".xml",".svg",".md",".csv",".yaml",".yml",".toml",".log",".ini",".conf"}
    async def preview(self,request):
        bucket,key,info,mime=await self.head(request)
        if not self.is_text(key,mime) or info.get("ContentEncoding"):
            raise self.Error(400,"preview_unavailable","此对象不支持文本预览，可下载查看。")
        data=b"";maximum=65536
        if info["ContentLength"]:
            result=await self.call(self.client(request["s3_credentials"]),"get_object",Bucket=bucket["name"],Key=key,
                Range="bytes=0-"+str(min(info["ContentLength"],maximum)-1),IfMatch=info["ETag"])
            try:data=await asyncio.to_thread(result["Body"].read,maximum)
            finally:result["Body"].close()
        return web.json_response({"text":data.decode("utf-8",errors="replace"),"truncated":info["ContentLength"]>maximum,
            "bytesRead":len(data),"limit":maximum})
    async def link(self,request):
        try:data=await request.json()
        except ValueError:raise self.Error(400,"invalid_json","请提供 JSON 请求。")
        if not isinstance(data,dict) or not {"bucket_id","key"}.issubset(data) or set(data)-{"bucket_id","key","inline"}:
            raise self.Error(400,"invalid_request","下载参数无效。")
        # Keys are passed as data, never as filesystem paths.
        bucket,key,info,mime=await self.head(request,data["bucket_id"],self.key(data["key"]))
        inline=data.get("inline",False)
        if type(inline) is not bool:raise self.Error(400,"invalid_request","inline 参数无效。")
        if inline and (mime not in RASTER or info["ContentLength"]>10*1024**2 or info.get("ContentEncoding")):
            raise self.Error(400,"preview_unavailable","仅支持不超过 10 MiB 的常见位图预览。")
        now=time.monotonic();self.tickets={key:value for key,value in self.tickets.items() if value["deadline"]>now}
        while len(self.tickets)>=128:self.tickets.pop(next(iter(self.tickets)))
        token=secrets.token_urlsafe(32)
        self.tickets[token]={"bucket":bucket,"key":key,"credentials":dict(request["s3_credentials"]),
            "principal":dict(request["principal"]),"etag":info.get("ETag"),"inline":inline,"mime":mime,"deadline":now+60}
        return web.json_response({"url":"/admin/download/"+token,"expiresIn":60})
    async def download(self,request):
        ticket=self.tickets.get(request.match_info["token"])
        if not ticket or ticket["deadline"]<=time.monotonic():raise self.Error(404,"download_link_expired","下载链接无效或已过期，请重新点击下载。")
        principal=ticket["principal"]
        if principal["tenant_id"]:
            record=await self.state.db("key",principal["key_id"])
            if not record or record["tenant_status"]!="active":raise self.Error(404,"download_link_expired","下载链接无效或已过期。")
            if not await self.state.db("bucket",ticket["bucket"]["id"],principal["tenant_id"]):raise self.Error(404,"bucket_not_found","没有找到该存储桶。")
        if self.slots.locked():raise self.Error(429,"downloads_busy","下载连接已满，请稍后重试。")
        async with self.slots:
            params={"Bucket":ticket["bucket"]["name"],"Key":ticket["key"]}
            if ticket["etag"]:params["IfMatch"]=ticket["etag"]
            requested=request.headers.get("Range")
            if requested:
                if not re.fullmatch(r"bytes=(?:[0-9]+-[0-9]*|-[0-9]+)",requested):raise self.Error(416,"invalid_range","仅支持单个下载范围。")
                params["Range"]=requested
            source=await self.call(self.client(ticket["credentials"]),"get_object",**params);body=source["Body"]
            filename=ticket["key"].rsplit("/",1)[-1] or "download"
            disposition=("inline" if ticket["inline"] else "attachment")+"; filename*=UTF-8''"+urllib.parse.quote(filename,safe="")
            headers={"Content-Type":ticket["mime"] if ticket["inline"] else "application/octet-stream",
                "Content-Disposition":disposition,"Accept-Ranges":"bytes","Content-Length":str(source["ContentLength"]),
                "Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","Content-Security-Policy":"sandbox"}
            if source.get("ContentRange"):headers["Content-Range"]=source["ContentRange"]
            response=web.StreamResponse(status=206 if source.get("ContentRange") else 200,headers=headers)
            try:
                await response.prepare(request)
                async with asyncio.timeout(6*3600):
                    sent=0
                    while True:
                        chunk=await asyncio.to_thread(body.read,65536)
                        if not chunk:break
                        await asyncio.wait_for(response.write(chunk),120);sent+=len(chunk)
                    if sent!=source["ContentLength"]:raise ConnectionResetError("Incomplete object stream")
                    await response.write_eof()
            except (ConnectionError,OSError,BotoCoreError,asyncio.TimeoutError,asyncio.CancelledError):
                if request.transport:request.transport.abort()
            finally:body.close()
            return response
    def attach(self,app):
        app.router.add_get("/admin/api/objects",self.listing)
        app.router.add_get("/admin/api/objects/detail",self.detail)
        app.router.add_get("/admin/api/objects/preview",self.preview)
        app.router.add_post("/admin/api/objects/link",self.link)
        app.router.add_get("/admin/download/{token}",self.download)
