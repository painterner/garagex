import asyncio
import gzip
import hashlib
import json
import os
import pathlib
import socket
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer
from botocore.exceptions import ClientError
from yarl import URL
from garagex.proxy.app import APIError,GuardedResolver,PublicPolicy,SERVICE,make_app

M=1024*1024

class FakeS3:
    def __init__(self):
        self.objects={};self.uploads={};self.part_count=0;self.aborts=0;self.fail=False
    def head_bucket(self,**kw): return {}
    def head_object(self,Key,**kw):
        if Key not in self.objects:
            raise ClientError({"Error":{"Code":"404"},"ResponseMetadata":{"HTTPStatusCode":404}},"HeadObject")
        return {"ContentLength":len(self.objects[Key])}
    def put_object(self,Key,Body,**kw):
        if self.fail: raise RuntimeError("simulated storage failure")
        self.objects[Key]=bytes(Body);return {}
    def create_multipart_upload(self,Key,**kw):
        ident=uuid.uuid4().hex;self.uploads[ident]=(Key,{})
        return {"UploadId":ident}
    def upload_part(self,UploadId,PartNumber,Body,**kw):
        if self.fail: raise RuntimeError("simulated storage failure")
        self.uploads[UploadId][1][PartNumber]=bytes(Body);self.part_count+=1
        return {"ETag":hashlib.md5(Body).hexdigest()}
    def complete_multipart_upload(self,UploadId,**kw):
        key,parts=self.uploads.pop(UploadId)
        self.objects[key]=b"".join(parts[i] for i in sorted(parts))
        return {}
    def abort_multipart_upload(self,UploadId,**kw):
        self.uploads.pop(UploadId,None);self.aborts+=1;return {}

class FixturePolicy(PublicPolicy):
    """Tests inject their loopback source. Production has no private-network switch."""
    def __init__(self,port):
        super().__init__(["8.8.8.8"]);self.port=port
    def url(self,value):
        if isinstance(value,str):
            url=URL(value,encoded=True)
            if url.scheme=="http" and url.host=="127.0.0.1" and url.port==self.port and url.user is None:
                return url
        return PublicPolicy(["8.8.8.8"]).url(value)
    def address(self,value):
        if value=="127.0.0.1": return value
        return super().address(value)

async def until(predicate,seconds=8):
    async with asyncio.timeout(seconds):
        while not predicate(): await asyncio.sleep(0.01)


class SignedClient:
    def __init__(self,credentials):
        self.credentials=credentials
        self.session=aiohttp.ClientSession(auto_decompress=False)
    async def request(self,method,url,**kwargs):
        import json
        from garagex.auth import signed_request
        data=None;headers={}
        if "json" in kwargs:
            data=json.dumps(kwargs.pop("json")).encode()
            headers["Content-Type"]="application/json"
        req=signed_request(self.credentials,str(url),data=data,method=method,headers=headers)
        return await self.session.request(method,url,data=data,headers=dict(req.header_items()),**kwargs)
    async def post(self,url,**kwargs):return await self.request("POST",url,**kwargs)
    async def get(self,url,**kwargs):return await self.request("GET",url,**kwargs)
    async def close(self):await self.session.close()

class Harness(unittest.IsolatedAsyncioTestCase):
    real=False
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.gate=asyncio.Event();self.sent_end=asyncio.Event()
        origin=web.Application()
        origin.router.add_get("/{name}",self.source)
        self.origin=TestServer(origin)
        await self.origin.start_server()
        self.cfg=dict(credentials={"access_key_id":"GKTESTKEY123","secret_access_key":"test-secret-only","region":"garage"},bucket="painterner",state_dir=self.tmp.name,
            max_concurrent=4,max_bytes=32*M,part_size=8*M,total_timeout=20,source_idle_timeout=10,
            client_write_timeout=5,continue_on_disconnect=True,key_prefix="proxy/",retention_seconds=3600)
        if self.real:
            import boto3
            from botocore.client import Config
            c=json.loads(pathlib.Path(os.environ.get("GARAGEX_CREDENTIALS","/etc/garagex/credentials.json")).read_text())
            self.cfg["bucket"]=c["bucket"]
            self.s3=boto3.client("s3",endpoint_url=os.environ.get("GARAGEX_S3_ENDPOINT","http://127.0.0.1:3900"),region_name=c["region"],
                aws_access_key_id=c["access_key_id"],aws_secret_access_key=c["secret_access_key"],
                config=Config(signature_version="s3v4",s3={"addressing_style":"path"}))
        else: self.s3=FakeS3()
        app=make_app(self.cfg,self.s3,FixturePolicy(self.origin.port))
        self.service=app[SERVICE]
        self.proxy=TestServer(app,handler_cancellation=True)
        await self.proxy.start_server()
        self.client=SignedClient(self.cfg["credentials"])
        self.keys=[]
    async def asyncTearDown(self):
        self.gate.set()
        await self.client.close()
        await self.proxy.close()
        await self.origin.close()
        if self.real and self.keys:
            await asyncio.to_thread(self.s3.delete_objects,Bucket=self.cfg["bucket"],
                Delete={"Objects":[{"Key":k} for k in self.keys],"Quiet":True})
        self.tmp.cleanup()
    async def source(self,request):
        name=request.match_info["name"]
        if name=="missing": return web.Response(status=404)
        if name=="redirect": raise web.HTTPFound("/small")
        if name=="private": raise web.HTTPFound("http://169.254.169.254/latest/meta-data/")
        if name=="empty": return web.Response(body=b"")
        if name=="gzip": return web.Response(body=gzip.compress(b"compressed data"*1000),headers={"Content-Encoding":"gzip"})
        if name=="oversize": return web.Response(status=200,headers={"Content-Length":str(100*M)})
        if name=="small": return web.Response(body=b"hello stream")
        total=20*M if name=="gated" else 12*M
        response=web.StreamResponse()
        if name=="truncated": response.content_length=24*M
        await response.prepare(request)
        try:
            for offset in range(0,total,65536):
                await response.write(b"z"*65536)
                if name=="gated" and offset+65536==10*M: await self.gate.wait()
                if name=="slow": await asyncio.sleep(0.002)
            if name=="truncated":
                request.transport.abort();return response
            self.sent_end.set()
            await response.write_eof()
        except ConnectionResetError: pass
        return response
    def key(self):
        value="proxy/.test-"+uuid.uuid4().hex+".bin";self.keys.append(value);return value
    async def post(self,name,key=None):
        key=key or self.key()
        r=await self.client.post(self.proxy.make_url("/_proxy/download"),
            json={"url":str(self.origin.make_url("/"+name)),"key":key})
        return r,key
    async def result(self,response):
        ident=response.headers["X-Download-Id"]
        await until(lambda:ident not in self.service.jobs)
        r=await self.client.get(self.proxy.make_url("/_proxy/jobs/"+ident))
        return await r.json()
    async def object_bytes(self,key):
        if not self.real: return self.s3.objects[key]
        r=await asyncio.to_thread(self.s3.get_object,Bucket=self.cfg["bucket"],Key=key)
        return await asyncio.to_thread(r["Body"].read)

class ProxyTests(Harness):
    async def test_stream_and_store_before_source_eof(self):
        r,key=await self.post("gated")
        self.assertEqual(r.status,200)
        first=await asyncio.wait_for(r.content.readexactly(64),2)
        self.assertEqual(first,b"z"*64)
        reader=asyncio.create_task(r.read())
        await until(lambda:self.s3.part_count>0)
        self.assertFalse(self.sent_end.is_set())
        self.assertNotIn(key,self.s3.objects)
        self.gate.set()
        data=first+await reader
        record=await self.result(r)
        self.assertEqual(len(data),20*M)
        self.assertEqual(self.s3.objects[key],data)
        self.assertEqual(record["state"],"completed")
        self.assertEqual(record["sha256"],hashlib.sha256(data).hexdigest())
    async def test_disconnect_continues_saving(self):
        r,key=await self.post("slow")
        await r.content.readexactly(64);r.close()
        record=await self.result(r)
        self.assertEqual(record["state"],"completed")
        self.assertFalse(record["client_connected"])
        self.assertEqual(self.s3.objects[key],b"z"*(12*M))
    async def test_zero_length_source(self):
        r,key=await self.post("empty")
        self.assertEqual(await r.read(),b"")
        self.assertEqual((await self.result(r))["state"],"completed")
        self.assertEqual(self.s3.objects[key],b"")
    async def test_compressed_bytes_preserved(self):
        r,key=await self.post("gzip");data=await r.read()
        self.assertEqual(r.headers["Content-Encoding"],"gzip")
        self.assertEqual(gzip.decompress(data),b"compressed data"*1000)
        self.assertEqual(self.s3.objects[key],data)
    async def test_redirect_checked_and_followed(self):
        r,key=await self.post("redirect")
        self.assertEqual(await r.read(),b"hello stream")
        self.assertEqual(self.s3.objects[key],b"hello stream")
    async def test_private_redirect_rejected(self):
        r,key=await self.post("private")
        self.assertEqual(r.status,400)
        self.assertEqual((await r.json())["error"]["code"],"blocked_source")
        self.assertNotIn(key,self.s3.objects)
    async def test_source_http_error(self):
        r,key=await self.post("missing")
        self.assertEqual(r.status,502)
        self.assertEqual((await r.json())["error"]["upstream_status"],404)
        self.assertNotIn(key,self.s3.objects)
    async def test_declared_size_limit(self):
        r,key=await self.post("oversize")
        self.assertEqual(r.status,413)
        self.assertNotIn(key,self.s3.objects)
    async def test_existing_object_not_overwritten(self):
        key=self.key();self.s3.objects[key]=b"original"
        r,_=await self.post("small",key)
        self.assertEqual(r.status,409)
        self.assertEqual(self.s3.objects[key],b"original")
    async def test_truncated_source_aborts_upload(self):
        r,key=await self.post("truncated")
        with self.assertRaises(aiohttp.ClientPayloadError): await r.read()
        record=await self.result(r)
        self.assertEqual(record["state"],"failed")
        self.assertNotIn(key,self.s3.objects)
        self.assertFalse(self.s3.uploads)
        self.assertGreater(self.s3.aborts,0)
    async def test_storage_failure_does_not_end_as_success(self):
        self.s3.fail=True
        r,key=await self.post("small")
        with self.assertRaises(aiohttp.ClientPayloadError): await r.read()
        self.assertEqual((await self.result(r))["state"],"failed")
        self.assertNotIn(key,self.s3.objects)
    async def test_auth_and_validation(self):
        async with aiohttp.ClientSession() as anonymous:
            r=await anonymous.post(self.proxy.make_url("/_proxy/download"),json={"url":"https://example.com"})
            self.assertEqual(r.status,401)
        for payload in [{"url":"file:///etc/passwd"},{"url":"http://127.0.0.1/"},{"url":"https://example.com","key":"wrong-prefix"}]:
            r=await self.client.post(self.proxy.make_url("/_proxy/download"),json=payload)
            self.assertEqual(r.status,400)
    async def test_key_lock_and_concurrency_limit(self):
        self.cfg["max_concurrent"]=1
        r,key=await self.post("gated")
        r2,_=await self.post("small")
        self.assertEqual(r2.status,429)
        self.gate.set();await r.read();await self.result(r)
    async def test_unknown_length_limit_aborts(self):
        self.cfg["max_bytes"]=9*M
        r,key=await self.post("slow")
        with self.assertRaises(aiohttp.ClientPayloadError): await r.read()
        self.assertEqual((await self.result(r))["error"]["code"],"source_too_large")
        self.assertFalse(self.s3.uploads)
    async def test_stop_on_disconnect_config(self):
        self.cfg["continue_on_disconnect"]=False
        r,key=await self.post("slow")
        await r.content.readexactly(64);r.close()
        record=await self.result(r)
        self.assertEqual(record["state"],"failed")
        self.assertNotIn(key,self.s3.objects)

class PolicyTests(unittest.IsolatedAsyncioTestCase):
    def test_literal_private_and_self_ips(self):
        policy=PublicPolicy(["8.8.8.8"])
        for value in ["http://127.0.0.1","http://[::1]","http://169.254.169.254/","http://10.0.0.1",
                      "http://8.8.8.8/","http://[::ffff:127.0.0.1]/","http://224.0.0.1","ftp://example.com"]:
            with self.assertRaises(APIError,msg=value): policy.url(value)
    async def test_dns_is_checked_and_pinned(self):
        policy=PublicPolicy()
        resolver=GuardedResolver(policy)
        loop=asyncio.get_running_loop()
        safe=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("8.8.8.8",443))]
        with patch.object(loop,"getaddrinfo",return_value=safe):
            result=await resolver.resolve("example.com",443)
            self.assertEqual(result[0]["host"],"8.8.8.8")
        unsafe=safe+[(socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",443))]
        with patch.object(loop,"getaddrinfo",return_value=unsafe):
            with self.assertRaises(APIError): await resolver.resolve("example.com",443)

@unittest.skipUnless(os.environ.get("TEST_REAL_S3")=="1","real Garage integration requires TEST_REAL_S3=1")
class RealGarageTests(Harness):
    real=True
    async def test_real_multipart_streams_before_eof(self):
        r,key=await self.post("gated")
        first=await asyncio.wait_for(r.content.readexactly(64),2)
        reader=asyncio.create_task(r.read())
        ident=r.headers["X-Download-Id"]
        await until(lambda:self.service.jobs[ident].record["bytes_stored"]>=8*M)
        job=self.service.jobs[ident]
        parts=await asyncio.to_thread(self.s3.list_parts,Bucket=self.cfg["bucket"],Key=key,UploadId=job.upload_id)
        self.assertGreaterEqual(len(parts["Parts"]),1)
        self.assertFalse(self.sent_end.is_set())
        self.gate.set();data=first+await reader
        record=await self.result(r)
        self.assertEqual(record["state"],"completed")
        stored=await self.object_bytes(key)
        self.assertEqual(hashlib.sha256(data).digest(),hashlib.sha256(stored).digest())
    async def test_real_disconnect_continues(self):
        r,key=await self.post("slow")
        await r.content.readexactly(64);r.close()
        self.assertEqual((await self.result(r))["state"],"completed")
        self.assertEqual(await self.object_bytes(key),b"z"*(12*M))
    async def test_real_empty_file(self):
        r,key=await self.post("empty");self.assertEqual(await r.read(),b"")
        self.assertEqual((await self.result(r))["state"],"completed")
        self.assertEqual(await self.object_bytes(key),b"")

if __name__=="__main__": unittest.main(verbosity=2)
