#!/usr/bin/env python3
"""Real isolated-stack tenant and object access checks. Removes its own objects/buckets/keys.
Run this against a disposable test installation: tenant audit/ownership rows are retained.
"""
import argparse,contextlib,json,pathlib,time,urllib.parse,urllib.request,uuid
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from garagex.auth import signed_request

def main():
    p=argparse.ArgumentParser()
    for name in ['credentials','s3','admin','proxy','garage-admin','garage-token']:p.add_argument('--'+name,required=True)
    args=p.parse_args();master=json.loads(pathlib.Path(args.credentials).read_text());keys=[];buckets=[];clients=[]
    token=pathlib.Path(args.garage_token).read_text().strip()
    def native(action,payload=None,query=None):
        data=json.dumps(payload).encode() if payload is not None else None
        request=urllib.request.Request(args.garage_admin+'/v2/'+action+('?' + urllib.parse.urlencode(query) if query else ''),data=data,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=20) as response:return json.load(response)
    def api(base,path,c=master,payload=None,method=None,status=200):
        body=json.dumps(payload).encode() if payload is not None else None
        request=signed_request(c,base+path,data=body,method=method or ('POST' if payload is not None else 'GET'))
        try:
            with urllib.request.urlopen(request,timeout=60) as response:
                assert response.status==status,(path,response.status,status)
                data=response.read();return data,response.headers
        except urllib.error.HTTPError as error:
            if error.code!=status:
                data=json.load(error)
                raise AssertionError((path,error.code,status,data.get('error',{}).get('code'))) from None
            return error.read(),error.headers
    def admin(path,c=master,payload=None,status=200):
        return json.loads(api(args.admin,'/admin/api'+path,c,payload,status=status)[0])
    def s3(c):
        client=boto3.client('s3',endpoint_url=args.s3,region_name=c['region'],aws_access_key_id=c['access_key_id'],aws_secret_access_key=c['secret_access_key'],
            config=Config(signature_version='s3v4',s3={'addressing_style':'path'},request_checksum_calculation='when_required',response_checksum_validation='when_required',retries={'max_attempts':0}))
        clients.append(client);return client
    def denied(operation):
        try:operation()
        except ClientError as error:
            assert error.response['ResponseMetadata']['HTTPStatusCode'] in {400,403,404,409,413,507};return
        raise AssertionError('Cross-tenant or over-quota S3 request was accepted')
    try:
        tenants=[]
        for name in ['one','two']:
            row=admin('/tenants',payload={'name':'integration-'+uuid.uuid4().hex[:8]+'-'+name,'request_id':str(uuid.uuid4()),'quota_bytes':2*1024**2,'max_buckets':2,'max_keys':4,'max_concurrent':1},status=201)
            c=row['credentials'];keys.append(c['access_key_id']);c['tenant_id']=row['tenant']['id'];tenants.append(c)
            b=admin('/buckets',c,{'name':'files','request_id':str(uuid.uuid4()),'quota_bytes':1024**2},status=201)['bucket'];buckets.append(b)
        a,b=tenants;ba,bb=buckets;sa,sb=s3(a),s3(b)
        key='folder/%literal 中 <script>.html';payload=b'<script>alert(1)</script>'
        sa.put_object(Bucket=ba['aliases'][0],Key=key,Body=payload,ContentType='text/html')
        denied(lambda:sb.get_object(Bucket=ba['aliases'][0],Key=key))
        assert [x['id'] for x in admin('/buckets',a)['items']]==[ba['id']]
        admin('/objects?'+urllib.parse.urlencode({'bucket_id':bb['id']}),a,status=404)
        admin('/keys/'+b['access_key_id']+'/reveal',a,{},status=404)
        admin('/tenants',a,status=403)
        print('Two tenants: console, keys and native S3 isolation PASS')
        params=urllib.parse.urlencode({'bucket_id':ba['id'],'mode':'flat'})
        objects=admin('/objects?'+params,a);assert any(x['key']==key for x in objects['items'])
        params=urllib.parse.urlencode({'bucket_id':ba['id'],'key':key})
        assert admin('/objects/preview?'+params,a)['text']==payload.decode()
        link=admin('/objects/link',a,{'bucket_id':ba['id'],'key':key})['url']
        with urllib.request.urlopen(args.admin+link) as response:
            assert response.read()==payload;assert response.headers['Content-Security-Policy']=='sandbox'
        print('Unicode/literal-percent keys, safe text preview and streaming download PASS')
        denied(lambda:sa.put_object(Bucket=ba['aliases'][0],Key='too-large',Body=b'x'*(2*1024**2)))
        admin('/buckets',a,{'name':'extra','request_id':str(uuid.uuid4()),'quota_bytes':2*1024**2},status=409)
        print('Native per-bucket quota and aggregate allocation limit PASS')
        app=admin('/keys',a,{'name':'integration-app','request_id':str(uuid.uuid4()),'grants':[{'bucketId':ba['id'],'read':True,'write':True}]},status=201)
        keys.append(app['key']['accessKeyId']);appc={**a,'access_key_id':app['key']['accessKeyId'],'secret_access_key':app['secretAccessKey']}
        admin('/session',appc,status=401)
        data,headers=api(args.proxy,'/_proxy/download',appc,{'url':'https://example.com/','bucket':ba['aliases'][0],'key':'proxy/integration-'+uuid.uuid4().hex,'retention_seconds':2})
        ident=headers['X-Download-Id']
        job=json.loads(api(args.proxy,'/_proxy/jobs/'+ident,appc)[0]);assert job['state']=='completed' and job['bucket']==ba['aliases'][0]
        assert sa.get_object(Bucket=job['bucket'],Key=job['key'])['Body'].read()==data
        api(args.proxy,'/_proxy/jobs/'+ident,b,status=404)
        api(args.proxy,'/_proxy/jobs/'+ident+'/report',b,status=404)
        api(args.proxy,'/_proxy/jobs/'+ident+'/observations',b,{'samples':[]},status=404)
        api(args.proxy,'/_proxy/jobs/'+ident,a)
        _,headers=api(args.proxy,'/_proxy/network/download?bytes=1024&seconds=0.1',appc)
        api(args.proxy,'/_proxy/network/results/'+headers['X-Network-Test-Id'],b,status=404)
        print('Tenant app proxy upload, report/observation/network isolation PASS')
        deadline=time.time()+15
        while time.time()<deadline:
            try:sa.head_object(Bucket=job['bucket'],Key=job['key'])
            except ClientError:break
            time.sleep(1)
        else:raise AssertionError('Tenant object retention cleanup failed')
        print('Tenant retention cleanup PASS')
        admin('/tenants/'+a['tenant_id']+'/status',payload={'status':'suspended'})
        admin('/session',a,status=401);api(args.proxy,'/_proxy/health',appc,status=401)
        denied(lambda:sa.head_bucket(Bucket=ba['aliases'][0]))
        admin('/tenants/'+a['tenant_id']+'/status',payload={'status':'active'});admin('/session',a)
        admin('/keys/'+appc['access_key_id']+'/revoke',a,{})
        api(args.proxy,'/_proxy/health',appc,status=401)
        print('Suspension disables native S3 and custom APIs; resume/revoke PASS')
    finally:
        # Only IDs returned by this run are removed; never enumerate-and-delete unrelated resources.
        cleanup=s3(master)
        for bucket in buckets:
            name=bucket['aliases'][0]
            try:
                for page in cleanup.get_paginator('list_objects_v2').paginate(Bucket=name):
                    objects=[{'Key':row['Key']} for row in page.get('Contents',[])]
                    if objects:cleanup.delete_objects(Bucket=name,Delete={'Objects':objects,'Quiet':True})
                native('DeleteBucket',{}, {'id':bucket['id']})
            except Exception as error:print('Test bucket cleanup needs attention:',type(error).__name__)
        for key in keys:
            try:native('DeleteKey',{}, {'id':key})
            except Exception:pass
        for client in clients:client.close()
if __name__=='__main__':main()
