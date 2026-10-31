import asyncio,json,pathlib,tempfile,unittest
from aiohttp import web
from aiohttp.test_utils import TestServer
from garagex.proxy.app import make_app,SERVICE
from garagex.tenants import Registry
from tests.proxy.test_proxy import FixturePolicy,SignedClient,until
from tests.proxy.test_features import MetadataS3
class Client(MetadataS3):
    def close(self):pass
class TenantProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=pathlib.Path(self.tmp.name);(root/'token').write_text('test-only-token')
        self.db=Registry(root/'registry.db');self.db.initialize();self.gate=asyncio.Event()
        self.identities={};self.clients=[];self.s3clients={}
        for name,role,tenant in [('owner','owner',None),('app','app','owner'),('other','owner',None)]:
            if tenant is None:
                row=self.db.create_tenant(name,1024**3,5,5,1);self.db.activate_tenant(row['id'])
            else:row=self.identities[tenant]['tenant']
            key='TEST'+name.upper();cred={'access_key_id':key,'secret_access_key':'test-'+name,'region':'garage'}
            reservation=self.db.reserve_key(row['id'],role);self.db.finish_key(reservation,key)
            if tenant is None:
                bucket=self.db.reserve_bucket(row['id'],'files',1024**2);bid=('a' if name=='owner' else 'b')*64
                self.db.finish_bucket(bucket['id'],bid)
            else:bucket=self.identities[tenant]['bucket'];bid=self.identities[tenant]['bid']
            self.identities[name]={'tenant':row,'bucket':bucket,'bid':bid,'credentials':cred}
            self.s3clients[key]=Client()
        source=web.Application()
        async def handle(request):
            if request.path=='/gated':
                response=web.StreamResponse();await response.prepare(request);await response.write(b'x'*100)
                await self.gate.wait();await response.write_eof();return response
            return web.Response(body=b'tenant fixture')
        source.router.add_get('/{name}',handle);self.origin=TestServer(source);await self.origin.start_server()
        self.master={'access_key_id':'TESTMASTER','secret_access_key':'test-master','region':'garage'}
        config=dict(credentials=self.master,bucket='root-files',state_dir=str(root/'jobs'),tenant_db=str(root/'registry.db'),
            garage_token_file=str(root/'token'),garage_url='http://unused.invalid',s3_endpoint='http://unused.invalid',
            max_concurrent=4,max_bytes=1024**2,part_size=8*1024**2,total_timeout=20,source_idle_timeout=10,client_write_timeout=5,
            continue_on_disconnect=True,key_prefix='proxy/',retention_seconds=3600)
        app=make_app(config,Client(),FixturePolicy(self.origin.port));self.service=app[SERVICE]
        async def key_info(key):
            info=next(v for v in self.identities.values() if v['credentials']['access_key_id']==key)
            return {'secretAccessKey':info['credentials']['secret_access_key'],'buckets':[{'id':info['bid'],'globalAliases':[info['bucket']['name']],'permissions':{'read':True,'write':True}}]}
        self.service.key_info=key_info;self.service.caller_client=lambda c:self.s3clients[c['access_key_id']]
        self.proxy=TestServer(app,handler_cancellation=True);await self.proxy.start_server()
        for info in self.identities.values():
            info['client']=SignedClient(info['credentials']);self.clients.append(info['client'])
    async def asyncTearDown(self):
        self.gate.set()
        for client in self.clients:await client.close()
        await self.proxy.close();await self.origin.close();self.tmp.cleanup()
    async def download(self,who,path='small',key='proxy/test'):
        info=self.identities[who]
        return await info['client'].post(self.proxy.make_url('/_proxy/download'),json={'url':str(self.origin.make_url('/'+path)),'bucket':info['bucket']['name'],'key':key})
    async def test_tenant_concurrency_and_bucket_selection(self):
        first=await self.download('owner','gated')
        self.assertEqual(first.status,200)
        second=await self.download('app','small','proxy/second');self.assertEqual(second.status,429)
        # Another tenant can use the same key in a different physical bucket.
        other=await self.download('other');self.assertEqual(other.status,200);await other.read()
        self.gate.set();await first.read()
        record=self.service.read_record(first.headers['X-Download-Id'])
        self.assertEqual(record['bucket'],self.identities['owner']['bucket']['name'])
        self.assertEqual(record['tenant_id'],self.identities['owner']['tenant']['id'])
    async def test_report_observations_and_app_job_ownership(self):
        response=await self.download('owner');await response.read();ident=response.headers['X-Download-Id']
        for who in ['app','other']:
            for suffix in ['', '/report']:
                r=await self.identities[who]['client'].get(self.proxy.make_url('/_proxy/jobs/'+ident+suffix));self.assertEqual(r.status,404)
            r=await self.identities[who]['client'].post(self.proxy.make_url('/_proxy/jobs/'+ident+'/observations'),json={'samples':[]});self.assertEqual(r.status,404)
        response=await self.download('app',key='proxy/app');await response.read()
        r=await self.identities['owner']['client'].get(self.proxy.make_url('/_proxy/jobs/'+response.headers['X-Download-Id']));self.assertEqual(r.status,200)
    async def test_cross_bucket_and_inactive_key_rejected(self):
        info=self.identities['owner'];r=await info['client'].post(self.proxy.make_url('/_proxy/download'),json={'url':str(self.origin.make_url('/small')),'bucket':self.identities['other']['bucket']['name']})
        self.assertEqual(r.status,404)
        self.db.set_status(info['tenant']['id'],'suspended')
        r=await info['client'].get(self.proxy.make_url('/_proxy/network/ping'));self.assertEqual(r.status,401)
    async def test_network_result_is_tenant_and_app_scoped(self):
        response=await self.identities['owner']['client'].get(self.proxy.make_url('/_proxy/network/download?bytes=100&seconds=0.1'));await response.read()
        path='/_proxy/network/results/'+response.headers['X-Network-Test-Id']
        for who in ['app','other']:
            r=await self.identities[who]['client'].get(self.proxy.make_url(path));self.assertEqual(r.status,404)
