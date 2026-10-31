import copy,io,json,tempfile,time,urllib.parse,unittest
from aiohttp.test_utils import AioHTTPTestCase
from garagex.admin.app import make_app,STATE
from garagex.auth import signed_request
from tests.admin.test_admin import MASTER,BUCKET
from tests.admin.fakes import TenantGarage
class FakeObjects:
    def __init__(self):
        self.payload=b'<script>alert(1)</script>';self.calls=[]
    def close(self):pass
    def list_objects_v2(self,**kwargs):
        self.calls.append(('list',kwargs))
        return {'EncodingType':'url','Contents':[{'Key':'dir%2F%25literal%20%E4%B8%AD.txt','Size':12}],'CommonPrefixes':[{'Prefix':'dir%2F'}],'IsTruncated':True,'NextContinuationToken':'opaque+/=token'}
    def head_object(self,**kwargs):
        self.calls.append(('head',kwargs));return {'ContentLength':len(self.payload),'ContentType':'text/html','ETag':'"fixed"','Metadata':{'name':'test'}}
    def get_object(self,**kwargs):
        self.calls.append(('get',kwargs));data=self.payload
        result={'Body':io.BytesIO(data),'ContentLength':len(data)}
        if kwargs.get('Range'):
            start,end=kwargs['Range'].removeprefix('bytes=').split('-');start=int(start);end=int(end or len(data)-1)
            data=data[start:end+1];result.update(Body=io.BytesIO(data),ContentLength=len(data),ContentRange=f'bytes {start}-{end}/{len(self.payload)}')
        return result
class ObjectTests(AioHTTPTestCase):
    async def get_application(self):
        self.objects=FakeObjects();self.garage=TenantGarage()
        return make_app({'credentials':MASTER,'origin':'https://s3.example.com'},self.garage,lambda _:self.objects)
    async def request(self,path,method='GET',payload=None):
        body=json.dumps(payload).encode() if payload is not None else None
        url=str(self.server.make_url('/admin/api'+path));signed=signed_request(MASTER,url,data=body,method=method)
        return await self.client.session.request(method,url,data=body,headers=dict(signed.header_items()))
    def query(self,key='dir/%literal 中.txt'):return urllib.parse.urlencode({'bucket_id':BUCKET,'key':key})
    async def test_list_decodes_exactly_once_and_preserves_cursor(self):
        response=await self.request('/objects?bucket_id='+BUCKET+'&cursor='+urllib.parse.quote('opaque+/=token',safe=''))
        self.assertEqual(response.status,200);data=await response.json()
        self.assertEqual(data['items'][0]['key'],'dir/%literal 中.txt');self.assertEqual(data['directories'],['dir/'])
        params=self.objects.calls[-1][1]
        self.assertEqual(params['ContinuationToken'],'opaque+/=token');self.assertEqual(params['Delimiter'],'/')
        response=await self.request('/objects?bucket_id='+BUCKET+'&mode=flat');self.assertEqual(response.status,200)
        self.assertNotIn('Delimiter',self.objects.calls[-1][1])
    async def test_html_and_svg_are_text_not_inline_active_content(self):
        response=await self.request('/objects/detail?'+self.query('evil.html'));data=await response.json()
        self.assertTrue(data['textPreview']);self.assertFalse(data['imagePreview'])
        response=await self.request('/objects/preview?'+self.query('evil.html'))
        self.assertEqual((await response.json())['text'],self.objects.payload.decode())
        response=await self.request('/objects/link','POST',{'bucket_id':BUCKET,'key':'evil.html','inline':True});self.assertEqual(response.status,400)
    async def test_link_stream_range_and_sandbox(self):
        response=await self.request('/objects/link','POST',{'bucket_id':BUCKET,'key':'../%literal 中.html'})
        self.assertEqual(response.status,200,await response.text());url=(await response.json())['url']
        response=await self.client.get(url)
        self.assertEqual(await response.read(),self.objects.payload)
        self.assertEqual(response.headers['Content-Type'],'application/octet-stream')
        self.assertTrue(response.headers['Content-Disposition'].startswith('attachment'))
        self.assertEqual(response.headers['Content-Security-Policy'],'sandbox')
        self.assertEqual(self.objects.calls[-1][1]['Key'],'../%literal 中.html')
        response=await self.client.get(url,headers={'Range':'bytes=0-3'})
        self.assertEqual(response.status,206);self.assertEqual(await response.read(),self.objects.payload[:4])
    async def test_expired_and_unknown_links_rejected(self):
        response=await self.request('/objects/link','POST',{'bucket_id':BUCKET,'key':'a.txt'});url=(await response.json())['url']
        self.app[STATE].objects.tickets[url.rsplit('/',1)[-1]]['deadline']=time.monotonic()-1
        response=await self.client.get(url);self.assertEqual(response.status,404)
        response=await self.client.get('/admin/download/unknown');self.assertEqual(response.status,404)
    async def test_invalid_key_and_page_size(self):
        for path in ['/objects?bucket_id='+BUCKET+'&limit=999','/objects/detail?bucket_id='+BUCKET]:
            response=await self.request(path);self.assertEqual(response.status,400)
