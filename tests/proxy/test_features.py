import asyncio,datetime,hashlib,json,pathlib,time,unittest,os
from unittest.mock import patch,AsyncMock
import aiohttp
from aiohttp.test_utils import TestServer
from garagex.proxy.app import make_app,SERVICE
from tests.proxy.test_proxy import Harness,FakeS3,FixturePolicy,until
from garagex.auth import signed_request

M=1024*1024
class MetadataS3(FakeS3):
    def __init__(self):super().__init__();self.metadata={};self.upload_metadata={}
    def put_object(self,Key,Body,Metadata=None,**kwargs):
        result=super().put_object(Key=Key,Body=Body,**kwargs)
        self.metadata[Key]=Metadata or {};return result
    def create_multipart_upload(self,Key,Metadata=None,**kwargs):
        result=super().create_multipart_upload(Key=Key,**kwargs)
        self.upload_metadata[result["UploadId"]]=Metadata or {};return result
    def complete_multipart_upload(self,UploadId,**kwargs):
        key=self.uploads[UploadId][0]
        result=super().complete_multipart_upload(UploadId=UploadId,**kwargs)
        self.metadata[key]=self.upload_metadata.pop(UploadId,{});return result
    def head_object(self,Key,**kwargs):
        result=super().head_object(Key=Key,**kwargs)
        result.update(Metadata=self.metadata.get(Key,{}),LastModified=datetime.datetime.now(datetime.timezone.utc))
        return result
    def delete_object(self,Key,**kwargs):
        self.objects.pop(Key,None);self.metadata.pop(Key,None);return {}

class FeatureTests(Harness):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.s3=MetadataS3();self.service.s3=self.s3
    async def custom(self,name,**options):
        key=options.pop("key",self.key())
        response=await self.client.post(self.proxy.make_url("/_proxy/download"),
            json={"url":str(self.origin.make_url("/"+name)),"key":key,**options})
        return response,key
    async def test_stop_keep_retains_prefix(self):
        r,key=await self.custom("slow",disconnect_mode="stop_keep")
        await r.content.readexactly(64);r.close()
        record=await self.result(r)
        self.assertEqual(record["state"],"stopped")
        self.assertTrue(record["is_partial"]);self.assertTrue(record["object_available"])
        self.assertGreater(record["bytes_stored"],0);self.assertLess(record["bytes_stored"],12*M)
        self.assertEqual(self.s3.objects[key],b"z"*record["bytes_stored"])
        self.assertEqual(record["sha256"],hashlib.sha256(self.s3.objects[key]).hexdigest())
        self.assertIsNone(record["expires_at"]);self.assertFalse(self.s3.uploads)
    async def test_stop_keep_after_s3_part_is_written(self):
        r,key=await self.custom("gated",disconnect_mode="stop_keep")
        reader=asyncio.create_task(r.read())
        await until(lambda:self.s3.part_count>=1)
        r.close()
        await asyncio.gather(reader,return_exceptions=True)
        record=await self.result(r)
        self.assertEqual(record["state"],"stopped")
        self.assertGreaterEqual(len(self.s3.objects[key]),8*M)
        self.assertLess(len(self.s3.objects[key]),20*M)
        self.assertFalse(self.s3.uploads)
    async def test_ttl_expiry_deletes_only_owned_object(self):
        r,key=await self.custom("small",retention_seconds=1);await r.read()
        record=await self.result(r)
        self.assertIsNotNone(record["expires_at"])
        with patch("garagex.proxy.features.time.time",return_value=time.time()+3):await self.service.expire_objects()
        self.assertNotIn(key,self.s3.objects)
        self.assertEqual(self.service.read_record(record["id"])["storage_state"],"expired")
    async def test_partial_ttl_cleanup(self):
        r,key=await self.custom("slow",disconnect_mode="stop_keep",retention_seconds=1)
        await r.content.readexactly(64);r.close();record=await self.result(r)
        self.assertIn(key,self.s3.objects)
        with patch("garagex.proxy.features.time.time",return_value=time.time()+3):await self.service.expire_objects()
        self.assertNotIn(key,self.s3.objects)
    async def test_replaced_object_is_not_deleted(self):
        r,key=await self.custom("small",retention_seconds=1);await r.read();record=await self.result(r)
        self.s3.put_object(Key=key,Body=b"replacement")
        with patch("garagex.proxy.features.time.time",return_value=time.time()+3):await self.service.expire_objects()
        self.assertEqual(self.s3.objects[key],b"replacement")
        self.assertEqual(self.service.read_record(record["id"])["storage_state"],"replaced")
    async def test_default_is_permanent(self):
        r,key=await self.custom("small");await r.read();record=await self.result(r)
        self.assertIsNone(record["download_retention_seconds"])
        with patch("garagex.proxy.features.time.time",return_value=time.time()+400*86400):await self.service.expire_objects()
        self.assertEqual(self.s3.objects[key],b"hello stream")
    async def test_expiry_plan_survives_service_restart(self):
        r,key=await self.custom("small",retention_seconds=1);await r.read();await self.result(r)
        await self.proxy.close()
        app=make_app(self.cfg,self.s3,FixturePolicy(self.origin.port))
        self.service=app[SERVICE];self.proxy=TestServer(app,handler_cancellation=True);await self.proxy.start_server()
        with patch("garagex.proxy.features.time.time",return_value=time.time()+3):await self.service.expire_objects()
        self.assertNotIn(key,self.s3.objects)
    async def test_report_and_client_observations(self):
        r,key=await self.custom("small");await r.read();record=await self.result(r);ident=record["id"]
        r=await self.client.get(self.proxy.make_url("/_proxy/jobs/"+ident+"/report"));report=await r.json()
        self.assertEqual(report["job"]["state"],"completed")
        self.assertGreater(report["sample_count"],0)
        self.assertEqual(report["summary"]["upstream_bytes"],len(b"hello stream"))
        self.assertEqual(report["downstream_client"]["measurement"],"not_available")
        samples=[{"elapsed_seconds":1,"received_bytes":5,"rtt_ms":10},{"elapsed_seconds":2,"received_bytes":12,"rtt_ms":20}]
        r=await self.client.post(self.proxy.make_url("/_proxy/jobs/"+ident+"/observations"),json={"samples":samples})
        self.assertEqual(r.status,200)
        r=await self.client.get(self.proxy.make_url("/_proxy/jobs/"+ident+"/report"));report=await r.json()
        self.assertEqual(report["downstream_client"]["rtt_ms"]["mean"],15)
        self.assertEqual(len(report["downstream_client"]["timeline"]),2)
        r=await self.client.get(self.proxy.make_url("/_proxy/jobs/"+ident+"/report?format=html"))
        self.assertEqual(r.content_type,"text/html")
        self.assertIn("<svg",await r.text())
    async def test_invalid_options_rejected(self):
        for options in [{"retention_seconds":0},{"retention_seconds":-1},{"retention_seconds":True},
                        {"disconnect_mode":"wrong"},{"retention_seconds":315360001}]:
            r,key=await self.custom("small",**options);self.assertEqual(r.status,400)
    async def test_pure_network_does_not_store_objects(self):
        r=await self.client.get(self.proxy.make_url("/_proxy/network/ping"));self.assertEqual(r.status,200)
        r=await self.client.get(self.proxy.make_url("/_proxy/network/download?bytes=131072&seconds=1"))
        ident=r.headers["X-Network-Test-Id"]
        self.assertEqual(len(await r.read()),131072)
        r=await self.client.get(self.proxy.make_url("/_proxy/network/results/"+ident))
        self.assertFalse((await r.json())["storage_payload_written"])
        r=await self.client.post(self.proxy.make_url("/_proxy/network/upstream"),
            json={"url":str(self.origin.make_url("/slow")),"bytes":M,"seconds":1})
        result=await r.json();self.assertEqual(result["received_bytes"],M)
        self.assertGreater(result["payload_mbps"],0)
        self.assertFalse(result["storage_payload_written"])
        self.assertFalse(self.s3.objects);self.assertFalse(self.s3.uploads)
    async def test_streamed_network_upload_and_hash_check(self):
        data=b"x"*(2*M);url=str(self.proxy.make_url("/_proxy/network/upload"))
        req=signed_request(self.cfg["credentials"],url,data=data,headers={"Content-Type":"application/octet-stream"})
        r=await self.client.session.post(url,data=data,headers=dict(req.header_items()))
        self.assertEqual(r.status,200);result=await r.json()
        self.assertEqual(result["received_bytes"],len(data));self.assertFalse(result["storage_payload_written"])
        r=await self.client.session.post(url,data=b"y"*len(data),headers=dict(req.header_items()))
        self.assertEqual(r.status,400)
        self.assertFalse(self.s3.objects)
    async def test_network_connection_error_is_json(self):
        with patch.object(self.service,"open_source",new=AsyncMock(side_effect=aiohttp.ClientConnectionError("test"))):
            r=await self.client.post(self.proxy.make_url("/_proxy/network/upstream"),
                json={"url":str(self.origin.make_url("/small"))})
            self.assertEqual(r.status,502)
            self.assertEqual((await r.json())["error"]["code"],"source_transfer_failed")
    async def test_network_sources_keep_ssrf_checks(self):
        r=await self.client.post(self.proxy.make_url("/_proxy/network/upstream"),json={"url":"http://169.254.169.254/","bytes":M})
        self.assertEqual(r.status,400)
        r=await self.client.get(self.proxy.make_url("/_proxy/network/download?bytes=536870913"))
        self.assertEqual(r.status,400)

@unittest.skipUnless(os.environ.get("TEST_REAL_S3")=="1","enable TEST_REAL_S3 for real integration tests")
class RealFeatureTests(Harness):
    real=True
    async def test_real_retained_partial_and_expiry(self):
        key=self.key()
        r=await self.client.post(self.proxy.make_url("/_proxy/download"),
            json={"url":str(self.origin.make_url("/slow")),"key":key,"disconnect_mode":"stop_keep","retention_seconds":1})
        await r.content.readexactly(64);r.close();record=await self.result(r)
        self.assertEqual(record["state"],"stopped")
        stored=await self.object_bytes(key)
        self.assertGreater(len(stored),0);self.assertLess(len(stored),12*M)
        self.assertEqual(stored,b"z"*len(stored))
        with patch("garagex.proxy.features.time.time",return_value=time.time()+3):await self.service.expire_objects()
        head=await asyncio.to_thread(self.s3.list_objects_v2,Bucket=self.cfg["bucket"],Prefix=key)
        self.assertFalse(head.get("Contents"))
    async def test_real_multipart_prefix_and_report(self):
        key=self.key()
        r=await self.client.post(self.proxy.make_url("/_proxy/download"),
            json={"url":str(self.origin.make_url("/gated")),"key":key,"disconnect_mode":"stop_keep"})
        reader=asyncio.create_task(r.read());ident=r.headers["X-Download-Id"]
        await until(lambda:self.service.jobs[ident].record["bytes_stored"]>=8*M)
        r.close();await asyncio.gather(reader,return_exceptions=True)
        record=await self.result(r)
        self.assertEqual(record["state"],"stopped")
        data=await self.object_bytes(key)
        self.assertGreaterEqual(len(data),8*M);self.assertLess(len(data),20*M)
        self.assertEqual(record["sha256"],hashlib.sha256(data).hexdigest())
        r=await self.client.get(self.proxy.make_url("/_proxy/jobs/"+ident+"/report"))
        report=await r.json();self.assertGreater(report["sample_count"],0)

if __name__=="__main__":unittest.main(verbosity=2)
