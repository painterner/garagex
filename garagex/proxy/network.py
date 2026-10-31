"""Storage-free HTTP payload benchmarks and public-upstream receive benchmarks."""
import asyncio,contextlib,hashlib,hmac,json,os,time,uuid
from aiohttp import web
import aiohttp
from .metrics import CURRENT,Meter,source_socket,stats

class NetworkTests:
    def __init__(self,service):
        self.service=service;self.results={};self.payload=os.urandom(65536)
    @contextlib.asynccontextmanager
    async def slot(self,request):
        maximum=self.service.config.get("network_max_concurrent",2)
        if self.service.network_active>=maximum:
            raise self.service.Err(429,"network_tests_busy","All network test slots are busy.")
        tenant=request.get("proxy_principal",{}).get("tenant_id")
        counts=getattr(self.service,"network_tenants",{})
        if tenant and counts.get(tenant,0)>=1:raise self.service.Err(429,"tenant_network_limit","One network test per tenant is allowed.")
        if tenant:counts[tenant]=counts.get(tenant,0)+1
        self.service.network_active+=1
        try:yield
        finally:
            self.service.network_active-=1
            if tenant:counts[tenant]-=1
            cutoff=time.time()-600
            for ident in list(self.results):
                if self.results[ident]["created_at"]<cutoff:self.results.pop(ident,None)
            while len(self.results)>128:self.results.pop(next(iter(self.results)))
    def limits(self,data):
        try:count=data.get("bytes",32*1024**2);seconds=data.get("seconds",5)
        except AttributeError:raise self.service.Err(400,"invalid_test","Provide an object of test settings.")
        if isinstance(count,str):
            try:count=int(count)
            except ValueError:pass
        if isinstance(seconds,str):
            try:seconds=float(seconds)
            except ValueError:pass
        if type(count) is not int or not 1<=count<=self.service.config.get("network_max_bytes",512*1024**2):
            raise self.service.Err(400,"invalid_test","bytes must be from 1 to 536870912.")
        if type(seconds) not in {int,float} or not 0.1<=seconds<=30:
            raise self.service.Err(400,"invalid_test","seconds must be from 0.1 to 30.")
        return count,seconds
    async def ping(self,request):
        return web.json_response({"server_time":time.time(),"measurement":"HTTP round-trip timing is measured by the caller.",
            "storage_payload_written":False},headers={"Cache-Control":"no-store"})
    async def result(self,request):
        row=self.results.get(request.match_info["id"])
        if row is None or time.time()-row["created_at"]>600:
            raise self.service.Err(404,"test_not_found","The in-memory network result expired or does not exist.")
        if hasattr(self.service,"authorize_record"):self.service.authorize_record(request,row)
        return web.json_response(row,headers={"Cache-Control":"no-store"})
    async def download(self,request):
        count,seconds=self.limits(request.query)
        async with self.slot(request):
            ident=uuid.uuid4().hex;meter=Meter();record={"id":ident,"created_at":time.time(),"state":"running",
                "direction":"service_to_downstream","storage_payload_written":False}
            if hasattr(self.service,"owner_fields"):record.update(self.service.owner_fields(request))
            self.results[ident]=record
            response=web.StreamResponse(headers={"Content-Type":"application/octet-stream","Content-Encoding":"identity",
                "Cache-Control":"no-store","X-Network-Test-Id":ident})
            await response.prepare(request)
            try:
                async with asyncio.timeout(seconds+10):
                    while meter.sent<count and time.monotonic()-meter.started<seconds:
                        chunk=self.payload[:min(len(self.payload),count-meter.sent)]
                        start=time.monotonic();await response.write(chunk)
                        meter.send(len(chunk),(time.monotonic()-start)*1000)
                    await response.write_eof()
                record["state"]="completed"
            except (asyncio.CancelledError,ConnectionError,asyncio.TimeoutError):
                record["state"]="interrupted"
                if request.transport:request.transport.abort()
            finally:
                meter.finish();record.update(summary=meter.summary(),timeline=meter.all_rows())
            return response
    async def upload(self,request):
        maximum=self.service.config.get("network_max_bytes",512*1024**2)
        if request.content_length is not None and request.content_length>maximum:
            raise self.service.Err(413,"test_too_large","The network upload exceeds 512 MiB.")
        async with self.slot(request):
            meter=Meter();digest=hashlib.sha256()
            try:
                async with asyncio.timeout(120):
                    async for chunk in request.content.iter_chunked(65536):
                        if meter.received+len(chunk)>maximum:
                            raise self.service.Err(413,"test_too_large","The network upload exceeds 512 MiB.")
                        digest.update(chunk);meter.receive(len(chunk))
            except asyncio.TimeoutError:
                raise self.service.Err(408,"test_upload_timeout","The network upload exceeded 120 seconds.")
            if not hmac.compare_digest(digest.hexdigest(),request.headers["X-Amz-Content-SHA256"]):
                raise self.service.Err(400,"payload_hash_mismatch","The upload does not match its signed SHA-256.")
            meter.finish()
            return web.json_response({"direction":"downstream_to_service","received_bytes":meter.received,
                "payload_mbps":round(meter.received*8/max(time.monotonic()-meter.started,1e-6)/1e6,6),
                "storage_payload_written":False,"summary":meter.summary(),"timeline":meter.all_rows()},
                headers={"Cache-Control":"no-store"})
    async def upstream(self,request):
        try:data=await request.json()
        except ValueError:raise self.service.Err(400,"invalid_json","The request body must be JSON.")
        if not isinstance(data,dict) or set(data)-{"url","bytes","seconds"}:
            raise self.service.Err(400,"invalid_test","Provide url and optional bytes and seconds.")
        count,seconds=self.limits(data)
        self.service.policy.url(data.get("url"))
        async with self.slot(request):
            meter=Meter();token=CURRENT.set(meter);source=None
            try:
                source=await self.service.open_source(data.get("url"))
                meter.sock=source_socket(source)
                meter.phases["headers_received_ms"]=(time.monotonic()-meter.started)*1000
                start=time.monotonic();reason="time_limit"
                while meter.received<count:
                    remaining=seconds-(time.monotonic()-start)
                    if remaining<=0:break
                    try:chunk=await asyncio.wait_for(source.content.read(min(65536,count-meter.received)),remaining)
                    except asyncio.TimeoutError:break
                    if not chunk:reason="source_eof";break
                    meter.receive(len(chunk))
                if meter.received>=count:reason="byte_limit"
                elapsed=max(time.monotonic()-start,1e-6)
                meter.finish();rows=meter.all_rows()
                return web.json_response({"direction":"upstream_to_service","received_bytes":meter.received,
                    "transfer_seconds":round(elapsed,6),"payload_mbps":round(meter.received*8/elapsed/1e6,6),
                    "stop_reason":reason,"storage_payload_written":False,
                    "summary":meter.summary(),"tcp_rtt_ms":stats([r.get("upstream_tcp_rtt_ms") for r in rows]),
                    "timeline":rows},headers={"Cache-Control":"no-store"})
            except (aiohttp.ClientError,asyncio.TimeoutError):
                raise self.service.Err(502,"source_transfer_failed","The upstream network test could not complete.")
            finally:
                if source:source.close()
                CURRENT.reset(token)
    def routes(self,app):
        app.router.add_get("/_proxy/network/ping",self.ping)
        app.router.add_get("/_proxy/network/download",self.download)
        app.router.add_post("/_proxy/network/upload",self.upload)
        app.router.add_post("/_proxy/network/upstream",self.upstream)
        app.router.add_get("/_proxy/network/results/{id}",self.result)
