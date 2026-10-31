"""Proxy process reports, stop-and-keep mode, and durable object expiry."""
import asyncio,base64,hashlib,json,logging,math,pathlib,re,time,urllib.parse,uuid
from dataclasses import dataclass,field
from aiohttp import web
import aiohttp
from botocore.exceptions import ClientError
from .metrics import CURRENT,Meter,source_socket,stats,report_rows

LOG=logging.getLogger("s3_proxy")

@dataclass
class TransferJob:
    id:str
    key:str
    url:str
    meta:object
    record:dict
    meter:object
    mode:str
    queue:object=field(default_factory=lambda:asyncio.Queue(maxsize=8))
    connected:bool=True
    cancel_requested:bool=False
    shutdown_requested:bool=False
    task:object=None
    error:object=None
    upload_id:object=None
    source:object=None
    opening:object=None
    def detach(self,keep_downloading):
        self.connected=False;self.record["client_connected"]=False
        if not keep_downloading and self.record["state"] not in {"completed","stopped","failed"}:
            self.cancel_requested=True
            self.meter.sample(True)
            if self.source:self.source.close()
            if self.opening and not self.opening.done():self.opening.cancel()
        while not self.queue.empty():self.queue.get_nowait()
    async def emit(self,data):
        while self.connected:
            try:
                await asyncio.wait_for(self.queue.put(data),0.25);return
            except asyncio.TimeoutError:continue

def enhanced_service(base,Error,END):
    class Service(base):
        Err=Error
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            self.expiry_dir=self.state_dir/"expiry";self.expiry_dir.mkdir(exist_ok=True)
            self.network_active=0
        def save(self,job):
            if hasattr(job,"meter"):job.record["metrics"]=job.meter.summary()
            super().save(job)
        def prune(self):
            cutoff=time.time()-self.config["retention_seconds"]
            for path in self.state_dir.glob("*.json"):
                if path.stem in self.jobs:continue
                try:
                    record=json.loads(path.read_text())
                    if record.get("finished_at",time.time())<cutoff:
                        for suffix in [".metrics.jsonl",".client.jsonl"]:
                            path.with_name(path.stem+suffix).unlink(missing_ok=True)
                except (ValueError,FileNotFoundError):continue
            super().prune()
        async def maintain(self):
            while True:
                try:await self.expire_objects();self.prune()
                except Exception as error:LOG.error("expiry_sweep_failed type=%s",type(error).__name__)
                await asyncio.sleep(self.config.get("cleanup_interval_seconds",5))
        async def start(self):
            await super().start()
            await self.expire_objects()
        async def close(self):
            for job in self.jobs.values():job.shutdown_requested=True
            await super().close()
        def _expiry(self,job,ready=False):
            ttl=job.record["download_retention_seconds"]
            if ttl is None:return
            path=self.expiry_dir/(job.id+".json")
            record={"id":job.id,"key":job.key,"bucket":job.record["bucket"],"retention_seconds":ttl,
                    "expires_at":job.record.get("expires_at") if ready else None}
            tmp=path.with_suffix(".tmp");tmp.write_text(json.dumps(record)+"\n");tmp.chmod(0o600);tmp.replace(path)
        async def expire_objects(self):
            now=time.time()
            for path in self.expiry_dir.glob("*.json"):
                plan=json.loads(path.read_text())
                if plan["id"] in self.jobs and plan.get("expires_at") is None:continue
                due=plan.get("expires_at")
                if due is not None and due>now:continue
                outcome="expired"
                try:
                    head=await self.s3call("head_object",Bucket=plan["bucket"],Key=plan["key"])
                except ClientError as error:
                    if error.response["ResponseMetadata"]["HTTPStatusCode"]!=404:raise
                    head=None
                if head is not None:
                    if head.get("Metadata",{}).get("proxy-job-id")!=plan["id"]:
                        outcome="replaced"
                    elif due is None:
                        modified=head.get("LastModified")
                        due=(modified.timestamp() if hasattr(modified,"timestamp") else now)+plan["retention_seconds"]
                        plan["expires_at"]=due
                        tmp=path.with_suffix(".tmp");tmp.write_text(json.dumps(plan)+"\n");tmp.replace(path)
                        if due>now:continue
                    if outcome!="replaced":
                        await self.s3call("delete_object",Bucket=plan["bucket"],Key=plan["key"])
                record_path=self.state_dir/(plan["id"]+".json")
                if record_path.exists():
                    record=json.loads(record_path.read_text())
                    record.update(storage_state=outcome,object_available=False,expired_at=now)
                    if plan["id"] in self.jobs:
                        self.jobs[plan["id"]].record.update(storage_state=outcome,object_available=False,expired_at=now)
                    tmp=record_path.with_suffix(".tmp");tmp.write_text(json.dumps(record)+"\n");tmp.chmod(0o600);tmp.replace(record_path)
                path.unlink(missing_ok=True)
        def submit(self,data,context=None):
            if self.stopping or len(self.jobs)>=self.config["max_concurrent"]:
                raise Error(429,"too_many_downloads","All download slots are busy. Retry later.")
            allowed={"url","key","disconnect_mode","retention_seconds"}
            if context is not None:allowed.add("bucket")
            if not isinstance(data,dict) or set(data)-allowed:
                raise Error(400,"invalid_request","Send url, optional key, disconnect_mode and retention_seconds.")
            mode=data.get("disconnect_mode","continue" if self.config["continue_on_disconnect"] else "stop")
            if mode not in {"continue","stop_keep"} and not (mode=="stop" and "disconnect_mode" not in data):
                raise Error(400,"invalid_disconnect_mode","disconnect_mode must be continue or stop_keep.")
            ttl=data.get("retention_seconds",self.config.get("download_retention_seconds"))
            if ttl is not None and (type(ttl) is not int or not 1<=ttl<=315360000):
                raise Error(400,"invalid_retention","retention_seconds must be null or an integer from 1 to 315360000.")
            url=self.policy.url(data.get("url"));key=self.choose_key(data,url)
            if context and context.get("tenant_id") and sum(j.record.get("tenant_id")==context["tenant_id"] for j in self.jobs.values())>=context["max_concurrent"]:
                raise Error(429,"tenant_download_limit","The tenant download concurrency limit is reached.")
            bucket=context["bucket"] if context is not None else self.config["bucket"]
            active_key=(bucket,key)
            if active_key in self.active_keys:raise Error(409,"key_busy","Another download is already writing this key.")
            ident=uuid.uuid4().hex
            record=dict(id=ident,state="starting",bucket=bucket,key=key,created_at=time.time(),
                bytes_downloaded=0,bytes_stored=0,client_connected=True,disconnect_mode=mode,
                download_retention_seconds=ttl,expires_at=None,is_partial=False,object_available=False,storage_state="pending")
            meta=asyncio.get_running_loop().create_future()
            meta.add_done_callback(lambda f:f.exception() if not f.cancelled() else None)
            job=TransferJob(ident,key,str(url),meta,record,Meter(self.state_dir/(ident+".metrics.jsonl")),mode)
            if context is not None:
                record.update(tenant_id=context["tenant_id"],access_key_id=context["key_id"])
                job.client=context.get("client")
            self.jobs[ident]=job;self.active_keys.add(active_key);self.save(job)
            job.task=asyncio.create_task(self.run_job(job),name="proxy-"+ident)
            return job
        async def monitor(self,job):
            while True:
                await asyncio.sleep(1);job.meter.sample(True)
        async def persist(self,job,storage,parts,buffer,digest,partial):
            self._expiry(job)
            job.record["state"]="committing";self.save(job)
            if job.upload_id is not None:
                if buffer:await self.upload_part(job,parts,bytes(buffer))
                await self.job_s3call(job,"complete_multipart_upload",Bucket=job.record["bucket"],Key=job.key,
                                 UploadId=job.upload_id,MultipartUpload={"Parts":parts})
                job.upload_id=None
            else:
                payload=bytes(buffer)
                await self.job_s3call(job,"put_object",**storage,Body=payload,ContentMD5=base64.b64encode(hashlib.md5(payload).digest()).decode())
            now=time.time();ttl=job.record["download_retention_seconds"]
            job.record.update(state="stopped" if partial else "completed",is_partial=partial,object_available=True,
                storage_state="retained",bytes_stored=job.record["bytes_downloaded"],sha256=digest.hexdigest(),
                finished_at=now,stored_at=now,expires_at=(now+ttl if ttl is not None else None))
            job.record.pop("_upload_id",None);self._expiry(job,True)
        async def run_job(self,job):
            source=None;buffer=bytearray();parts=[];digest=hashlib.sha256();storage=None
            token=CURRENT.set(job.meter);monitor=asyncio.create_task(self.monitor(job))
            try:
                try:await self.job_s3call(job,"head_object",Bucket=job.record["bucket"],Key=job.key)
                except ClientError as e:
                    if e.response["ResponseMetadata"]["HTTPStatusCode"]!=404:raise
                else:raise Error(409,"object_exists","This S3 key already exists; choose a new key.")
                if job.cancel_requested:raise Error(499,"download_cancelled","The caller disconnected before download began.")
                job.opening=asyncio.create_task(self.open_source(job.url))
                source=await job.opening;job.source=source
                job.meter.sock=source_socket(source)
                job.meter.phases["headers_received_ms"]=(time.monotonic()-job.meter.started)*1000
                length=source.content_length
                if length is not None and length>self.config["max_bytes"]:
                    raise Error(413,"source_too_large","The source exceeds the configured file-size limit.")
                content_type=source.headers.get("Content-Type","application/octet-stream")[:512]
                encoding=source.headers.get("Content-Encoding")
                metadata={"proxy-job-id":job.id,"disconnect-mode":job.mode}
                if length is not None:metadata["expected-bytes"]=str(length)
                storage=dict(Bucket=job.record["bucket"],Key=job.key,ContentType=content_type,Metadata=metadata)
                if encoding:storage["ContentEncoding"]=encoding
                job.record.update(state="downloading",content_type=content_type,source_size=length);self.save(job)
                job.meta.set_result(dict(content_type=content_type,encoding=encoding,length=length))
                async with asyncio.timeout(self.config["total_timeout"]):
                    while True:
                        if job.cancel_requested:raise Error(499,"download_cancelled","The downstream caller disconnected.")
                        chunk=await source.content.read(65536)
                        if not chunk:break
                        if job.record["bytes_downloaded"]+len(chunk)>self.config["max_bytes"]:
                            raise Error(413,"source_too_large","The source exceeds the configured file-size limit.")
                        job.record["bytes_downloaded"]+=len(chunk);job.meter.receive(len(chunk))
                        digest.update(chunk);buffer.extend(chunk);await job.emit(chunk)
                        if len(buffer)>=self.config["part_size"]:
                            if job.upload_id is None:
                                self._expiry(job)
                                upload=await self.job_s3call(job,"create_multipart_upload",**storage)
                                job.upload_id=upload["UploadId"];job.record["_upload_id"]=job.upload_id;self.save(job)
                            payload=bytes(buffer[:self.config["part_size"]]);del buffer[:self.config["part_size"]]
                            await self.upload_part(job,parts,payload)
                    if job.cancel_requested:raise Error(499,"download_cancelled","The downstream caller disconnected.")
                    if length is not None and job.record["bytes_downloaded"]!=length:
                        raise Error(502,"truncated_source","The source ended before the complete file arrived.")
                    await self.persist(job,storage,parts,buffer,digest,False)
            except (Exception,asyncio.CancelledError) as error:
                if job.cancel_requested and job.mode=="stop_keep" and not job.shutdown_requested:
                    try:
                        if source:source.close()
                        if storage is not None and job.record["bytes_downloaded"]:
                            await self.persist(job,storage,parts,buffer,digest,True)
                        else:job.record.update(state="stopped",is_partial=True,finished_at=time.time())
                    except Exception as storage_error:
                        job.error=Error(502,"partial_save_failed","The received prefix could not be retained.")
                        job.record.update(state="failed",error={"code":job.error.code,"message":job.error.message},finished_at=time.time())
                        LOG.warning("partial_save_failed id=%s type=%s",job.id,type(storage_error).__name__)
                else:
                    if isinstance(error,Error):job.error=error
                    elif isinstance(error,asyncio.CancelledError):job.error=Error(503,"service_stopped","The service stopped before the job finished.")
                    elif isinstance(error,(aiohttp.ClientError,asyncio.TimeoutError,OSError)):
                        job.error=Error(502,"source_transfer_failed","The source connection failed or timed out.")
                    else:job.error=Error(502,"storage_or_transfer_failed","The file could not be saved completely.")
                    job.record.update(state="failed",error={"code":job.error.code,"message":job.error.message,**job.error.details},finished_at=time.time())
                    LOG.warning("download_failed id=%s code=%s type=%s",job.id,job.error.code,type(error).__name__)
            finally:
                job.meter.sample(True)
                if source:source.close()
                job.source=None
                if job.upload_id is not None:
                    try:
                        await self.job_s3call(job,"abort_multipart_upload",Bucket=job.record["bucket"],Key=job.key,UploadId=job.upload_id)
                        job.record.pop("_upload_id",None)
                    except Exception:LOG.error("multipart_cleanup_failed id=%s",job.id)
                if not job.meta.done():job.meta.set_exception(job.error or Error(499,"download_cancelled","The caller disconnected."))
                monitor.cancel();await asyncio.gather(monitor,return_exceptions=True)
                job.meter.finish();self.save(job)
                await job.emit(END)
                self.jobs.pop(job.id,None);self.active_keys.discard((job.record["bucket"],job.key))
                if getattr(job,"client",None):job.client.close()
                CURRENT.reset(token)
        async def download(self,request):
            try:data=await request.json()
            except (ValueError,UnicodeError):raise Error(400,"invalid_json","The request body must be JSON.")
            context=await self.prepare_download(request,data) if hasattr(self,"prepare_download") else None
            try:job=self.submit(data,context)
            except BaseException:
                if context and context.get("client"):context["client"].close()
                raise
            response=None;finished=False
            try:
                meta=await asyncio.shield(job.meta)
                headers={"Cache-Control":"no-store","Content-Type":meta["content_type"],"X-Content-Type-Options":"nosniff",
                    "X-Download-Id":job.id,"X-Download-Status-Url":"/_proxy/jobs/"+job.id,
                    "X-Download-Report-Url":"/_proxy/jobs/"+job.id+"/report",
                    "X-Download-Elapsed-Seconds":str(round(time.monotonic()-job.meter.started,5)),
                    "X-S3-Bucket":job.record["bucket"],"X-S3-Key":urllib.parse.quote(job.key,safe="/"),
                    "Content-Disposition":"attachment; filename*=UTF-8''"+urllib.parse.quote(job.key.rsplit("/",1)[-1],safe="")}
                if meta["encoding"]:headers["Content-Encoding"]=meta["encoding"]
                if meta["length"] is not None:headers["X-Source-Content-Length"]=str(meta["length"])
                response=web.StreamResponse(status=200,headers=headers);response.enable_chunked_encoding()
                await response.prepare(request)
                while True:
                    chunk=await job.queue.get()
                    if chunk is END:
                        if job.record["state"]!="completed":raise ConnectionResetError("The download did not complete.")
                        await response.write_eof();finished=True;return response
                    started=time.monotonic()
                    await asyncio.wait_for(response.write(chunk),self.config["client_write_timeout"])
                    job.meter.send(len(chunk),(time.monotonic()-started)*1000)
            except (ConnectionError,asyncio.TimeoutError):
                if request.transport:request.transport.abort()
                if response is not None:return response
                raise
            finally:
                if not finished:job.record["downstream_disconnected_at"]=time.time()
                job.detach(True if finished else job.mode=="continue")
                job.meter.sample(True)
                if job.record["state"] in {"completed","stopped","failed"}:job.meter.finish()
                self.save(job)
        def read_record(self,ident,request=None):
            if not re.fullmatch(r"[0-9a-f]{32}",ident):raise Error(404,"job_not_found","No such download job.")
            if ident in self.jobs:record=dict(self.jobs[ident].record);record["metrics"]=self.jobs[ident].meter.summary()
            else:
                path=self.state_dir/(ident+".json")
                if not path.exists():raise Error(404,"job_not_found","No such download job.")
                record=json.loads(path.read_text())
            if request is not None and hasattr(self,"authorize_record"):self.authorize_record(request,record)
            record.pop("_upload_id",None)
            return record
        async def status(self,request):
            return web.json_response(self.read_record(request.match_info["id"],request),headers={"Cache-Control":"no-store"})
        async def report(self,request):
            ident=request.match_info["id"];record=self.read_record(ident,request)
            try:max_points=int(request.query.get("max_points","1000"))
            except ValueError:raise Error(400,"invalid_limit","max_points must be an integer.")
            if not 1<=max_points<=10000:raise Error(400,"invalid_limit","max_points must be from 1 to 10000.")
            rows=[]
            path=self.state_dir/(ident+".metrics.jsonl")
            if path.exists():
                for line in path.read_text().splitlines():
                    try:rows.append(json.loads(line))
                    except ValueError:pass
            observations=[]
            client_path=self.state_dir/(ident+".client.jsonl")
            if client_path.exists():
                for line in client_path.read_text().splitlines():
                    try:observations.append(json.loads(line))
                    except ValueError:pass
            for index,row in enumerate(observations):
                previous=observations[index-1] if index else {"elapsed_seconds":0,"received_bytes":0}
                duration=row["elapsed_seconds"]-previous["elapsed_seconds"]
                row["receive_mbps"]=(row["received_bytes"]-previous["received_bytes"])*8/duration/1e6 if duration>0 else 0
            result={"job":record,"summary":record.get("metrics",{}),"sample_count":len(rows),
                "downsampled":len(rows)>max_points,"timeline":report_rows(rows,max_points),
                "upstream_tcp_rtt_ms":stats([v.get("upstream_tcp_rtt_ms") for v in rows]),
                "upstream_mbps":stats([v.get("upstream_mbps") for v in rows]),
                "downstream_server_write_mbps":stats([v.get("downstream_mbps") for v in rows]),
                "downstream_client":{"measurement":"client_reported_http_keepalive_rtt_and_received_bytes" if observations else "not_available",
                    "rtt_ms":stats([v.get("rtt_ms") for v in observations]),
                    "receive_mbps":stats([v.get("receive_mbps") for v in observations]),
                    "timeline":observations[::max(1,math.ceil(len(observations)/max_points))]}}
            if request.query.get("format")=="html":
                from .reporting import render_report
                return web.Response(text=render_report(result),content_type="text/html",headers={"Cache-Control":"no-store"})
            return web.json_response(result,headers={"Cache-Control":"no-store"})
        async def observations(self,request):
            ident=request.match_info["id"];self.read_record(ident,request)
            try:data=await request.json()
            except ValueError:raise Error(400,"invalid_json","The request body must be JSON.")
            samples=data.get("samples") if isinstance(data,dict) else None
            if not isinstance(samples,list) or not 1<=len(samples)<=60:raise Error(400,"invalid_samples","Provide 1 to 60 client samples.")
            path=self.state_dir/(ident+".client.jsonl")
            existing=path.read_text().splitlines() if path.exists() else []
            if len(existing)+len(samples)>30000:raise Error(413,"too_many_samples","This job already has the maximum client samples.")
            previous=json.loads(existing[-1]) if existing else {"elapsed_seconds":0,"received_bytes":0}
            clean=[]
            for sample in samples:
                if not isinstance(sample,dict) or set(sample)-{"elapsed_seconds","received_bytes","rtt_ms"}:
                    raise Error(400,"invalid_samples","Unexpected client sample fields.")
                elapsed=sample.get("elapsed_seconds");received=sample.get("received_bytes");rtt=sample.get("rtt_ms")
                if (type(elapsed) not in {int,float} or not math.isfinite(elapsed) or not previous["elapsed_seconds"]<=elapsed<=self.config["total_timeout"]+300
                    or type(received) is not int or not previous["received_bytes"]<=received<=self.config["max_bytes"]
                    or (rtt is not None and (type(rtt) not in {int,float} or not math.isfinite(rtt) or not 0<=rtt<=120000))):
                    raise Error(400,"invalid_samples","Client sample counters and timings must be finite and monotonic.")
                row={"elapsed_seconds":elapsed,"received_bytes":received,"rtt_ms":rtt,"received_at":time.time()}
                clean.append(row);previous=row
            with path.open("a") as stream:
                for row in clean:stream.write(json.dumps(row)+"\n")
            return web.json_response({"accepted":len(clean)})
    return Service
