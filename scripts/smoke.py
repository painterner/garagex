#!/usr/bin/env python3
"""Read-only authenticated API checks plus a temporary S3 object roundtrip."""
import argparse,json,pathlib,uuid,urllib.request
import boto3
from botocore.client import Config
from garagex.auth import signed_request

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--credentials',required=True)
    parser.add_argument('--s3',required=True)
    parser.add_argument('--admin',required=True)
    parser.add_argument('--proxy',required=True)
    args=parser.parse_args()
    credentials=json.loads(pathlib.Path(args.credentials).read_text())
    options=dict(signature_version='s3v4',s3={'addressing_style':'path'},request_checksum_calculation='when_required',response_checksum_validation='when_required')
    client=boto3.client('s3',endpoint_url=args.s3,region_name=credentials['region'],aws_access_key_id=credentials['access_key_id'],aws_secret_access_key=credentials['secret_access_key'],config=Config(**options))
    key='garagex-check/'+uuid.uuid4().hex+'.txt';payload=b'GarageX isolated deployment check'
    try:
        client.put_object(Bucket=credentials['bucket'],Key=key,Body=payload)
        result=client.get_object(Bucket=credentials['bucket'],Key=key)
        try: assert result['Body'].read()==payload
        finally: result['Body'].close()
        print('S3 temporary object roundtrip: PASS')
    finally:
        client.delete_object(Bucket=credentials['bucket'],Key=key);client.close()
    for base,path in [(args.admin,'/admin/api/session'),(args.admin,'/admin/api/buckets'),(args.proxy,'/_proxy/health')]:
        with urllib.request.urlopen(signed_request(credentials,base+path),timeout=20) as response:
            assert response.status==200
            json.load(response)
        print(path+': PASS')
    try:
        urllib.request.urlopen(args.admin+'/admin/api/session',timeout=10)
        raise AssertionError('Anonymous API was accepted')
    except urllib.error.HTTPError as error: assert error.code==401
    print('Anonymous management access rejected: PASS')
if __name__=='__main__':main()
