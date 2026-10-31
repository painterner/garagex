import asyncio,json,tempfile,uuid,unittest
from pathlib import Path
from aiohttp.test_utils import AioHTTPTestCase
from garagex.admin.app import make_app,STATE
from garagex.auth import signed_request
from garagex.tenants import Registry,TenantError
from tests.admin.test_admin import MASTER
from tests.admin.fakes import TenantGarage
class TenantTests(AioHTTPTestCase):
    async def get_application(self):
        self.tmp=tempfile.TemporaryDirectory();self.garage=TenantGarage()
        self.addCleanup(self.tmp.cleanup)
        return make_app({'credentials':MASTER,'origin':'https://s3.example.com','tenant_db':self.tmp.name+'/registry.db'},self.garage)
    async def request(self,path,credentials=None,method='GET',payload=None):
        body=json.dumps(payload).encode() if payload is not None else None
        url=str(self.server.make_url('/admin/api'+path))
        signed=signed_request(credentials or MASTER,url,data=body,method=method)
        return await self.client.session.request(method,url,data=body,headers=dict(signed.header_items()))
    async def tenant(self,name='Customer',**limits):
        response=await self.request('/tenants',method='POST',payload={'name':name,'request_id':str(uuid.uuid4()),**limits})
        self.assertEqual(response.status,201,await response.text())
        return await response.json()
    async def bucket(self,credentials,name='files',quota=1024**3,request_id=None):
        response=await self.request('/buckets',credentials,method='POST',payload={'name':name,'quota_bytes':quota,'request_id':request_id or str(uuid.uuid4())})
        self.assertEqual(response.status,201,await response.text());return (await response.json())['bucket']
    async def test_owner_session_buckets_keys_and_quota(self):
        tenant=await self.tenant();credentials=tenant['credentials']
        response=await self.request('/session',credentials);session=await response.json()
        self.assertEqual(session['role'],'tenant');self.assertNotIn('adminKeyId',session)
        bucket=await self.bucket(credentials)
        self.assertTrue(bucket['aliases'][0].startswith(tenant['tenant']['prefix']))
        self.assertEqual(bucket['quotas']['maxSize'],1024**3)
        self.assertEqual(len(bucket['keys']),1)
        response=await self.request('/usage',credentials);usage=await response.json()
        self.assertEqual(usage['allocated_bytes'],1024**3);self.assertEqual(usage['bucket_count'],1)
    async def test_cross_tenant_resources_and_platform_endpoints_denied(self):
        a=await self.tenant('A');b=await self.tenant('B');bucket=await self.bucket(b['credentials'])
        for path in ['/tenants','/keys/'+b['credentials']['access_key_id']+'/reveal']:
            response=await self.request(path,a['credentials'],method='POST' if path.endswith('/reveal') else 'GET',payload={} if path.endswith('/reveal') else None)
            self.assertIn(response.status,{403,404})
        response=await self.request('/objects?bucket_id='+bucket['id'],a['credentials']);self.assertEqual(response.status,404)
        response=await self.request('/buckets',a['credentials']);self.assertEqual((await response.json())['items'],[])
        response=await self.request('/keys',a['credentials']);self.assertEqual(len((await response.json())['items']),1)
        response=await self.request('/keys',a['credentials'],method='POST',payload={'name':'bad','request_id':str(uuid.uuid4()),'grants':[{'bucketId':bucket['id'],'read':True,'write':True}]})
        self.assertEqual(response.status,404)
    async def test_app_key_cannot_login_and_can_be_revoked(self):
        tenant=await self.tenant();credentials=tenant['credentials'];bucket=await self.bucket(credentials)
        response=await self.request('/keys',credentials,method='POST',payload={'name':'app','request_id':str(uuid.uuid4()),'grants':[{'bucketId':bucket['id'],'read':True,'write':True}]})
        self.assertEqual(response.status,201);result=await response.json()
        app={**credentials,'access_key_id':result['key']['accessKeyId'],'secret_access_key':result['secretAccessKey']}
        response=await self.request('/session',app);self.assertEqual(response.status,401)
        response=await self.request('/keys/'+app['access_key_id']+'/revoke',credentials,method='POST',payload={});self.assertEqual(response.status,200)
        self.assertIsNone(self.app[STATE].registry.key(app['access_key_id']))
        response=await self.request('/keys/'+credentials['access_key_id']+'/revoke',credentials,method='POST',payload={});self.assertEqual(response.status,409)
    async def test_idempotency_cache_is_tenant_scoped(self):
        a=await self.tenant('A');b=await self.tenant('B');ident=str(uuid.uuid4())
        aa=await self.bucket(a['credentials'],request_id=ident);bb=await self.bucket(b['credentials'],request_id=ident)
        self.assertNotEqual(aa['id'],bb['id']);self.assertNotEqual(aa['aliases'],bb['aliases'])
    async def test_quota_limit_and_rollback(self):
        tenant=await self.tenant(quota_bytes=2*1024**2,max_buckets=1)
        await self.bucket(tenant['credentials'],quota=2*1024**2)
        response=await self.request('/buckets',tenant['credentials'],method='POST',payload={'name':'extra','request_id':str(uuid.uuid4()),'quota_bytes':1024**2})
        self.assertEqual(response.status,409)
        second=await self.tenant('second',quota_bytes=2*1024**2)
        response=await self.request('/buckets',second['credentials'],method='POST',payload={'name':'big','request_id':str(uuid.uuid4()),'quota_bytes':3*1024**2})
        self.assertEqual(response.status,409)
        self.garage.fail_allow=True
        response=await self.request('/buckets',second['credentials'],method='POST',payload={'name':'fails','request_id':str(uuid.uuid4()),'quota_bytes':1024**2})
        self.assertEqual(response.status,502)
        self.assertEqual(self.app[STATE].registry.allocated(second['tenant']['id']),0)
    async def test_suspend_expires_native_keys(self):
        tenant=await self.tenant();credentials=tenant['credentials'];ident=tenant['tenant']['id']
        response=await self.request('/tenants/'+ident+'/status',method='POST',payload={'status':'suspended'});self.assertEqual(response.status,200)
        self.assertTrue(self.garage.keys[credentials['access_key_id']]['expired'])
        response=await self.request('/session',credentials);self.assertEqual(response.status,401)
        response=await self.request('/tenants/'+ident+'/status',method='POST',payload={'status':'active'});self.assertEqual(response.status,200)
        response=await self.request('/session',credentials);self.assertEqual(response.status,200)
class RegistryTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_quota_reservation_is_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Registry(Path(directory)/'tenants.db');db.initialize();tenant=db.create_tenant('A',1024**2,10,5,2);db.activate_tenant(tenant['id'])
            results=await asyncio.gather(*(db.call('reserve_bucket',tenant['id'],name,1024**2) for name in ['one','two']),return_exceptions=True)
            self.assertEqual(sum(isinstance(r,TenantError) for r in results),1);self.assertEqual(db.allocated(tenant['id']),1024**2)
