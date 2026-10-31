#!/usr/bin/env python3
"""Authenticated streaming HTTP download to the caller and Garage S3."""
import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import pathlib
import re
import secrets
import socket
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractResolver
from botocore.exceptions import ClientError
from yarl import URL

LOG=logging.getLogger("s3_proxy")
END=object()
SERVICE=web.AppKey("service", object)

class APIError(Exception):
    def __init__(self,status,code,message,**details):
        self.status,self.code,self.message,self.details=status,code,message,details
        super().__init__(code)

class PublicPolicy:
    def __init__(self,blocked_ips=()):
        self.blocked={ipaddress.ip_address(x) for x in blocked_ips}
    def address(self,value):
        ip=ipaddress.ip_address(value)
        ip=getattr(ip,"ipv4_mapped",None) or ip
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip in self.blocked:
            raise APIError(400,"blocked_source","Only public external source addresses are accepted.")
        return ip
    def url(self,value):
        if not isinstance(value,str) or len(value)>8192 or any(ord(c)<32 for c in value):
            raise APIError(400,"invalid_url","Provide an HTTP or HTTPS URL.")
        try:
            url=URL(value,encoded=True)
            if url.scheme not in {"http","https"} or not url.raw_host or url.user is not None or url.password is not None or url.port not in {80,443}:
                raise ValueError()
            host=url.raw_host
            if "%" in host: raise ValueError()
            try: ipaddress.ip_address(host)
            except ValueError:
                if not re.fullmatch(r"[A-Za-z0-9.-]+",host): raise ValueError()
            else: self.address(host)
            return url.with_fragment(None)
        except APIError: raise
        except (ValueError,UnicodeError):
            raise APIError(400,"invalid_url","Use HTTP/HTTPS on port 80 or 443, without URL user credentials.")

class GuardedResolver(AbstractResolver):
    def __init__(self,policy): self.policy=policy
    async def resolve(self,host,port=0,family=socket.AF_INET):
        entries=await asyncio.get_running_loop().getaddrinfo(host,port,family=family,type=socket.SOCK_STREAM)
        results=[]; seen=set()
        for af,kind,proto,canon,addr in entries:
            self.policy.address(addr[0])
            if (af,addr[0]) not in seen:
                seen.add((af,addr[0]))
                results.append(dict(hostname=host,host=addr[0],port=port,family=af,proto=proto,flags=socket.AI_NUMERICHOST))
        if not results: raise OSError("No source DNS addresses.")
        return results
    async def close(self): pass

@dataclass
class Job:
    id:str
    key:str
    url:str
    meta:asyncio.Future
    record:dict
    queue:asyncio.Queue=field(default_factory=lambda:asyncio.Queue(maxsize=8))
    connected:bool=True
    cancel_requested:bool=False
    task:object=None
    error:object=None
    upload_id:object=None
    def detach(self,keep_downloading):
        self.connected=False
        self.record["client_connected"]=False
        if not keep_downloading: self.cancel_requested=True
        while not self.queue.empty(): self.queue.get_nowait()
    async def emit(self,data):
        while self.connected:
            try:
                await asyncio.wait_for(self.queue.put(data),0.5)
                return
            except asyncio.TimeoutError: continue

class ProxyService:
    def __init__(self,config,s3,policy=None):
        self.config,self.s3=config,s3
        self.policy=policy or PublicPolicy(config.get("blocked_ips",[]))
        self.state_dir=pathlib.Path(config["state_dir"])
        self.state_dir.mkdir(parents=True,exist_ok=True)
        self.jobs={}; self.active_keys=set()
        self.session=None; self.stopping=False; self.janitor=None
    async def s3call(self,operation,**kwargs):
        return await asyncio.to_thread(getattr(self.s3,operation),**kwargs)
    async def job_s3call(self,job,operation,**kwargs):
        return await asyncio.to_thread(getattr(getattr(job,"client",None) or self.s3,operation),**kwargs)
    def save(self,job):
        path=self.state_dir/(job.id+".json")
        tmp=path.with_suffix(".tmp")
        tmp.write_text(json.dumps(job.record,ensure_ascii=False)+"\n")
        tmp.chmod(0o600); tmp.replace(path)
    def prune(self):
        cutoff=time.time()-self.config["retention_seconds"]
        for path in self.state_dir.glob("*.json"):
            if path.stem in self.jobs: continue
            try:
                record=json.loads(path.read_text())
                if record.get("finished_at",time.time())<cutoff: path.unlink()
            except (ValueError,FileNotFoundError): pass
    async def maintain(self):
        while True:
            await asyncio.sleep(3600)
            self.prune()
    async def start(self):
        connector=aiohttp.TCPConnector(resolver=GuardedResolver(self.policy),use_dns_cache=False,
            limit=self.config["max_concurrent"],force_close=True)
        from .metrics import trace_config
        self.session=aiohttp.ClientSession(connector=connector,cookie_jar=aiohttp.DummyCookieJar(),trace_configs=[trace_config()],
            auto_decompress=False,trust_env=False,
            timeout=aiohttp.ClientTimeout(total=self.config["total_timeout"],connect=20,sock_read=self.config["source_idle_timeout"]),
            headers={"Accept-Encoding":"identity","User-Agent":"GarageX-Proxy/1.0"})
        try:
            await self.s3call("head_bucket",Bucket=self.config["bucket"])
            for path in self.state_dir.glob("*.json"):
                record=json.loads(path.read_text())
                if record["state"] not in {"starting","downloading","committing"}: continue
                upload=record.get("_upload_id")
                if upload:
                    try:
                        await self.s3call("abort_multipart_upload",Bucket=record.get("bucket",self.config["bucket"]),Key=record["key"],UploadId=upload)
                    except ClientError as e:
                        if e.response.get("Error",{}).get("Code")!="NoSuchUpload": raise
                record.update(state="failed",finished_at=time.time(),error={"code":"service_restarted","message":"The service restarted before this job finished."})
                record.pop("_upload_id",None)
                tmp=path.with_suffix(".tmp")
                tmp.write_text(json.dumps(record)+"\n");tmp.chmod(0o600);tmp.replace(path)
            self.prune()
            self.janitor=asyncio.create_task(self.maintain())
        except BaseException:
            await self.session.close()
            raise
    async def close(self):
        self.stopping=True
        if self.janitor:
            self.janitor.cancel()
            await asyncio.gather(self.janitor,return_exceptions=True)
        tasks=[]
        for job in self.jobs.values():
            job.detach(False);tasks.append(job.task)
        if tasks: await asyncio.gather(*tasks,return_exceptions=True)
        if self.session: await self.session.close()
    def choose_key(self,data,url):
        key=data.get("key")
        if key is None:
            name=urllib.parse.unquote(url.path.rsplit("/",1)[-1]) or "download.bin"
            name=re.sub(r"[\x00-\x1f\x7f/\\]","_",name)[:160]
            key=self.config["key_prefix"]+time.strftime("%Y/%m/%d/",time.gmtime())+uuid.uuid4().hex+"-"+name
        if not isinstance(key,str) or not key.startswith(self.config["key_prefix"]) or len(key.encode())>1024 or any(ord(c)<32 or ord(c)==127 for c in key) or any(part in {".",".."} for part in key.split("/")):
            raise APIError(400,"invalid_key","The key must start with "+self.config["key_prefix"]+" and contain at most 1024 UTF-8 bytes.")
        return key
    def submit(self,data):
        if self.stopping or len(self.jobs)>=self.config["max_concurrent"]:
            raise APIError(429,"too_many_downloads","All download slots are busy. Retry later.")
        if not isinstance(data,dict) or set(data)-{"url","key"}:
            raise APIError(400,"invalid_request","Send a JSON object with url and optional key.")
        url=self.policy.url(data.get("url"));key=self.choose_key(data,url)
        if key in self.active_keys: raise APIError(409,"key_busy","Another download is already writing this key.")
        ident=uuid.uuid4().hex
        record=dict(id=ident,state="starting",bucket=self.config["bucket"],key=key,created_at=time.time(),
                    bytes_downloaded=0,bytes_stored=0,client_connected=True)
        meta=asyncio.get_running_loop().create_future()
        meta.add_done_callback(lambda f:f.exception() if not f.cancelled() else None)
        job=Job(ident,key,str(url),meta,record)
        self.save(job);self.jobs[ident]=job;self.active_keys.add(key)
        job.task=asyncio.create_task(self.run_job(job),name="proxy-"+ident)
        return job
    async def open_source(self,value):
        url=self.policy.url(value)
        for index in range(6):
            response=await self.session.get(url,allow_redirects=False)
            if response.status in {301,302,303,307,308}:
                location=response.headers.get("Location");response.close()
                if index==5 or not location: raise APIError(502,"redirect_error","The source returned an invalid redirect chain.")
                url=self.policy.url(str(url.join(URL(location,encoded=True))))
                continue
            if response.status!=200:
                status=response.status;response.close()
                raise APIError(502,"source_http_error","The source did not return HTTP 200.",upstream_status=status)
            return response
        raise APIError(502,"redirect_error","Too many redirects.")
    async def upload_part(self,job,parts,payload):
        result=await self.job_s3call(job,"upload_part",Bucket=job.record["bucket"],Key=job.key,UploadId=job.upload_id,
            PartNumber=len(parts)+1,Body=payload,ContentMD5=base64.b64encode(hashlib.md5(payload).digest()).decode())
        parts.append({"PartNumber":len(parts)+1,"ETag":result["ETag"]})
        job.record["bytes_stored"]+=len(payload);self.save(job)
    async def run_job(self,job):
        source=None
        try:
            try: await self.s3call("head_object",Bucket=self.config["bucket"],Key=job.key)
            except ClientError as e:
                if e.response["ResponseMetadata"]["HTTPStatusCode"]!=404: raise
            else: raise APIError(409,"object_exists","This S3 key already exists; choose a new key.")
            source=await self.open_source(job.url);length=source.content_length
            if length is not None and length>self.config["max_bytes"]:
                raise APIError(413,"source_too_large","The source exceeds the configured file-size limit.")
            content_type=source.headers.get("Content-Type","application/octet-stream")[:512]
            encoding=source.headers.get("Content-Encoding")
            storage=dict(Bucket=self.config["bucket"],Key=job.key,ContentType=content_type,Metadata={"proxy-job-id":job.id})
            if encoding: storage["ContentEncoding"]=encoding
            job.record.update(state="downloading",content_type=content_type,source_size=length);self.save(job)
            job.meta.set_result(dict(content_type=content_type,encoding=encoding,length=length))
            digest=hashlib.sha256();buffer=bytearray();parts=[]
            async with asyncio.timeout(self.config["total_timeout"]):
                async for chunk in source.content.iter_chunked(65536):
                    if job.cancel_requested: raise APIError(499,"download_cancelled","The download was cancelled.")
                    job.record["bytes_downloaded"]+=len(chunk)
                    if job.record["bytes_downloaded"]>self.config["max_bytes"]:
                        raise APIError(413,"source_too_large","The source exceeds the configured file-size limit.")
                    digest.update(chunk);buffer.extend(chunk)
                    await job.emit(chunk)
                    if len(buffer)>=self.config["part_size"]:
                        if job.upload_id is None:
                            upload=await self.s3call("create_multipart_upload",**storage)
                            job.upload_id=upload["UploadId"];job.record["_upload_id"]=job.upload_id;self.save(job)
                        payload=bytes(buffer[:self.config["part_size"]]);del buffer[:self.config["part_size"]]
                        await self.upload_part(job,parts,payload)
                if job.cancel_requested: raise APIError(499,"download_cancelled","The download was cancelled.")
                if length is not None and job.record["bytes_downloaded"]!=length:
                    raise APIError(502,"truncated_source","The source ended before the complete file arrived.")
                job.record["state"]="committing";self.save(job)
                if job.upload_id is not None:
                    if buffer: await self.upload_part(job,parts,bytes(buffer))
                    await self.s3call("complete_multipart_upload",Bucket=self.config["bucket"],Key=job.key,
                                     UploadId=job.upload_id,MultipartUpload={"Parts":parts})
                    job.upload_id=None
                else:
                    payload=bytes(buffer)
                    await self.s3call("put_object",**storage,Body=payload,ContentMD5=base64.b64encode(hashlib.md5(payload).digest()).decode())
            job.record.update(state="completed",bytes_stored=job.record["bytes_downloaded"],sha256=digest.hexdigest(),finished_at=time.time())
            job.record.pop("_upload_id",None);self.save(job)
        except asyncio.CancelledError:
            job.error=APIError(503,"service_stopped","The service stopped before this job finished.")
            job.record.update(state="failed",error=dict(code=job.error.code,message=job.error.message),finished_at=time.time())
        except Exception as e:
            if isinstance(e,APIError): job.error=e
            elif isinstance(e,(aiohttp.ClientError,asyncio.TimeoutError,OSError)):
                job.error=APIError(502,"source_transfer_failed","The source connection failed or timed out.")
            else: job.error=APIError(502,"storage_or_transfer_failed","The file could not be saved completely.")
            job.record.update(state="failed",error=dict(code=job.error.code,message=job.error.message,**job.error.details),finished_at=time.time())
            LOG.warning("download_failed id=%s code=%s type=%s",job.id,job.error.code,type(e).__name__)
        finally:
            if source: source.close()
            if job.upload_id is not None:
                try:
                    await self.s3call("abort_multipart_upload",Bucket=self.config["bucket"],Key=job.key,UploadId=job.upload_id)
                    job.record.pop("_upload_id",None)
                except Exception: LOG.error("multipart_cleanup_failed id=%s",job.id)
            if not job.meta.done(): job.meta.set_exception(job.error or APIError(502,"download_failed","The download failed."))
            self.save(job)
            await job.emit(END)
            self.jobs.pop(job.id,None);self.active_keys.discard(job.key)
    async def download(self,request):
        try: data=await request.json()
        except (ValueError,UnicodeError): raise APIError(400,"invalid_json","The request body must be JSON.")
        job=self.submit(data);response=None
        try:
            meta=await asyncio.shield(job.meta)
            headers={"Cache-Control":"no-store","Content-Type":meta["content_type"],"X-Content-Type-Options":"nosniff",
                "X-Download-Id":job.id,"X-Download-Status-Url":"/_proxy/jobs/"+job.id,
                "X-S3-Bucket":self.config["bucket"],"X-S3-Key":urllib.parse.quote(job.key,safe="/"),
                "Content-Disposition":"attachment; filename*=UTF-8''"+urllib.parse.quote(job.key.rsplit("/",1)[-1],safe="")}
            if meta["encoding"]: headers["Content-Encoding"]=meta["encoding"]
            if meta["length"] is not None: headers["X-Source-Content-Length"]=str(meta["length"])
            response=web.StreamResponse(status=200,headers=headers);response.enable_chunked_encoding()
            await response.prepare(request)
            while True:
                chunk=await job.queue.get()
                if chunk is END:
                    if job.record["state"]!="completed": raise ConnectionResetError("S3 commit did not succeed.")
                    await response.write_eof()
                    return response
                await asyncio.wait_for(response.write(chunk),self.config["client_write_timeout"])
        except (ConnectionError,asyncio.TimeoutError):
            if request.transport: request.transport.abort()
            if response is not None: return response
            raise
        finally:
            job.detach(self.config["continue_on_disconnect"]);self.save(job)
    async def status(self,request):
        ident=request.match_info["id"]
        if not re.fullmatch(r"[0-9a-f]{32}",ident): raise APIError(404,"job_not_found","No such download job.")
        if ident in self.jobs: record=dict(self.jobs[ident].record)
        else:
            path=self.state_dir/(ident+".json")
            if not path.exists(): raise APIError(404,"job_not_found","No such download job.")
            record=json.loads(path.read_text())
        record.pop("_upload_id",None)
        return web.json_response(record,headers={"Cache-Control":"no-store"})

@web.middleware
async def errors(request,handler):
    try: return await handler(request)
    except APIError as e:
        headers={"Cache-Control":"no-store"}
        if e.status==401: headers["WWW-Authenticate"]="AWS4-HMAC-SHA256"
        return web.json_response({"error":dict(code=e.code,message=e.message,**e.details)},status=e.status,headers=headers)
@web.middleware
async def auth(request,handler):
    from garagex.auth import verify_signature, SignatureError
    try:
        body=None if request.method=="POST" and request.path=="/_proxy/network/upload" else await request.read()
        service=request.app[SERVICE]
        if hasattr(service,"authenticate"):await service.authenticate(request,body)
        else:verify_signature(request.method,request.raw_path,request.headers,body,service.config["credentials"])
    except SignatureError as error:
        raise APIError(401,"unauthorized",str(error))
    return await handler(request)

def make_app(config,s3,policy=None):
    from .features import enhanced_service
    service_type=enhanced_service(ProxyService,APIError,END)
    if config.get("tenant_db"):
        from .tenancy import tenant_service
        service_type=tenant_service(service_type,APIError)
    service=service_type(config,s3,policy)
    app=web.Application(middlewares=[errors,auth],client_max_size=32768)
    app[SERVICE]=service
    app.router.add_post("/_proxy/download",service.download)
    app.router.add_get("/_proxy/jobs/{id}",service.status)
    app.router.add_get("/_proxy/jobs/{id}/report",service.report)
    app.router.add_post("/_proxy/jobs/{id}/observations",service.observations)
    from .network import NetworkTests
    service.network=NetworkTests(service)
    service.network.routes(app)
    async def health(request):
        principal=request.get("proxy_principal",{})
        active=len(service.jobs) if not principal.get("tenant_id") else sum(j.record.get("tenant_id")==principal["tenant_id"] for j in service.jobs.values())
        return web.json_response({"status":"ok","active_downloads":active})
    app.router.add_get("/_proxy/health",health)
    async def lifecycle(app):
        await service.start()
        try: yield
        finally: await service.close()
    app.cleanup_ctx.append(lifecycle)
    return app

def main():
    import boto3
    from botocore.client import Config
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",default="/etc/garagex/proxy.json")
    config=json.loads(pathlib.Path(parser.parse_args().config).read_text())
    config["credentials"]=json.loads(pathlib.Path(config["credentials_file"]).read_text())
    credentials=config["credentials"]
    s3=boto3.client("s3",endpoint_url=config["s3_endpoint"],region_name=credentials["region"],
        aws_access_key_id=credentials["access_key_id"],aws_secret_access_key=credentials["secret_access_key"],
        config=Config(signature_version="s3v4",s3={"addressing_style":"path"},connect_timeout=10,read_timeout=30,
                      retries={"max_attempts":2},max_pool_connections=8))
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    web.run_app(make_app(config,s3),host=config.get("host","127.0.0.1"),port=config["port"],access_log=None,handler_cancellation=True,shutdown_timeout=100)
if __name__=="__main__": main()
