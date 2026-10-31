"""Tenant authentication and resource checks for the extension APIs."""
import asyncio,pathlib,re,sqlite3
import aiohttp,boto3
from botocore.client import Config
from garagex.auth import verify_signature,SignatureError
from garagex.tenants import Registry,request_key

def tenant_service(base,Error):
    class Service(base):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            self.registry=Registry(self.config['tenant_db'],readonly=True)
            self.identity=None;self.network_tenants={}
        async def start(self):
            token=pathlib.Path(self.config['garage_token_file']).read_text().strip()
            self.identity=aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                headers={'Authorization':'Bearer '+token},trust_env=False,cookie_jar=aiohttp.DummyCookieJar())
            try:await super().start()
            except BaseException:
                await self.identity.close();raise
        async def close(self):
            try:await super().close()
            finally:
                if self.identity:await self.identity.close()
        async def key_info(self,key):
            try:
                async with self.identity.get(self.config['garage_url']+'/v2/GetKeyInfo',
                    params={'id':key,'showSecretKey':'true'},allow_redirects=False) as response:
                    if response.status!=200:raise SignatureError('S3 key is unavailable.')
                    return await response.json()
            except (aiohttp.ClientError,asyncio.TimeoutError):raise Error(503,'identity_unavailable','Key verification service is unavailable.')
        async def authenticate(self,request,body):
            master=self.config['credentials'];key=request_key(request.headers)
            if key==master['access_key_id']:
                verify_signature(request.method,request.raw_path,request.headers,body,master)
                request['proxy_principal']={'tenant_id':None,'key_id':key,'role':'platform'}
                request['proxy_credentials']=master;return
            try:record=await self.registry.call('key',key) if key else None
            except OSError:raise Error(503,'identity_unavailable','Tenant registry is not ready.')
            except sqlite3.OperationalError:raise Error(503,'identity_unavailable','Tenant registry is not ready.')
            if not record or record['tenant_status']!='active':raise SignatureError('Invalid or inactive S3 key.')
            info=await self.key_info(key)
            if info.get('expired') or not info.get('secretAccessKey'):raise SignatureError('Invalid or expired S3 key.')
            credentials={'access_key_id':key,'secret_access_key':info['secretAccessKey'],'region':master['region']}
            verify_signature(request.method,request.raw_path,request.headers,body,credentials)
            request['proxy_principal']={'tenant_id':record['tenant_id'],'key_id':key,'role':record['role'],'max_concurrent':record['max_concurrent']}
            request['proxy_credentials']=credentials;request['proxy_key_info']=info
        def authorize_record(self,request,record):
            principal=request['proxy_principal']
            if principal['role']=='platform':return
            if record.get('tenant_id')!=principal['tenant_id'] or (principal['role']!='owner' and record.get('access_key_id')!=principal['key_id']):
                raise Error(404,'job_not_found','No such download job or network result.')
        def owner_fields(self,request):
            principal=request.get('proxy_principal',{})
            return {'tenant_id':principal.get('tenant_id'),'access_key_id':principal.get('key_id')}
        def caller_client(self,credentials):
            return boto3.client('s3',endpoint_url=self.config['s3_endpoint'],region_name=credentials['region'],
                aws_access_key_id=credentials['access_key_id'],aws_secret_access_key=credentials['secret_access_key'],
                config=Config(signature_version='s3v4',s3={'addressing_style':'path'},connect_timeout=10,read_timeout=30,
                    max_pool_connections=2,retries={'max_attempts':2},request_checksum_calculation='when_required',response_checksum_validation='when_required'))
        async def prepare_download(self,request,data):
            if not isinstance(data,dict):raise Error(400,'invalid_request','Provide a JSON object.')
            principal=request['proxy_principal'];tenant=principal['tenant_id']
            if tenant and sum(job.record.get('tenant_id')==tenant for job in self.jobs.values())>=principal['max_concurrent']:
                raise Error(429,'tenant_download_limit','The tenant download concurrency limit is reached.')
            hint=data.get('bucket')
            if hint is not None and (not isinstance(hint,str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,62}[a-z0-9]',hint)):
                raise Error(400,'invalid_bucket','Use the physical S3 bucket name or bucket ID.')
            if tenant is None and hint is None:
                return {'bucket':self.config['bucket'],'tenant_id':None,'key_id':principal['key_id']}
            info=request.get('proxy_key_info') or await self.key_info(principal['key_id'])
            buckets=[]
            for bucket in info.get('buckets',[]):
                permissions=bucket.get('permissions',{})
                if not permissions.get('read') or not permissions.get('write'):continue
                if tenant and not await self.registry.call('bucket',bucket['id'],tenant):continue
                aliases=bucket.get('globalAliases',[])
                if aliases and (hint is None or hint in [bucket['id'],*aliases]):buckets.append((bucket,aliases[0] if hint==bucket['id'] or hint is None else hint))
            if len(buckets)!=1:raise Error(404 if hint else 400,'bucket_required','Choose one of your S3 buckets with both read and write permissions.')
            credentials=request['proxy_credentials'];client=None
            if tenant:client=self.caller_client(credentials)
            return {'bucket':buckets[0][1],'tenant_id':tenant,'key_id':principal['key_id'],'client':client,'max_concurrent':principal.get('max_concurrent',4)}
    return Service
