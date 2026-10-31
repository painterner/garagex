"""Authentication security checks against independently generated SDK signatures."""
import datetime
import hashlib
import unittest
from urllib.parse import urlsplit
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from multidict import CIMultiDict
from garagex.auth import SignatureError,verify_signature

CREDS={"access_key_id":"GKTESTKEY123","secret_access_key":"test-secret-only","region":"garage"}

def sign(method="POST",path="/_proxy/download",body=b'{"url":"https://example.com/file"}',creds=None):
    credentials=creds or CREDS
    aws=AWSRequest(method=method,url="https://s3.example.test"+path,data=body,
                   headers={"Host":"s3.example.test","Content-Type":"application/json"})
    S3SigV4Auth(Credentials(credentials["access_key_id"],credentials["secret_access_key"]),"s3",credentials["region"]).add_auth(aws)
    return CIMultiDict(aws.headers.items()),body

class SignatureTests(unittest.TestCase):
    def test_valid_post_and_empty_get(self):
        for method,path,body in [("POST","/_proxy/download",b'{"url":"https://example.com/a?z=1"}'),
                                 ("GET","/_proxy/health",b""),("GET","/_proxy/health?a=1&z=2",b"")]:
            headers,_=sign(method,path,body)
            verify_signature(method,path,headers,body,CREDS)
    def test_changed_body_rejected(self):
        headers,body=sign()
        with self.assertRaises(SignatureError):
            verify_signature("POST","/_proxy/download",headers,body+b" ",CREDS)
    def test_wrong_secret_rejected(self):
        headers,body=sign(creds={**CREDS,"secret_access_key":"wrong"})
        with self.assertRaises(SignatureError):verify_signature("POST","/_proxy/download",headers,body,CREDS)
    def test_wrong_access_key_rejected(self):
        headers,body=sign(creds={**CREDS,"access_key_id":"GKWRONG"})
        with self.assertRaises(SignatureError):verify_signature("POST","/_proxy/download",headers,body,CREDS)
    def test_wrong_region_rejected(self):
        headers,body=sign(creds={**CREDS,"region":"elsewhere"})
        with self.assertRaises(SignatureError):verify_signature("POST","/_proxy/download",headers,body,CREDS)
    def test_host_path_query_and_method_tampering_rejected(self):
        headers,body=sign()
        for method,path in [("GET","/_proxy/download"),("POST","/_proxy/health"),("POST","/_proxy/download?a=1")]:
            with self.assertRaises(SignatureError):verify_signature(method,path,headers,body,CREDS)
        headers["Host"]="changed.example.test"
        with self.assertRaises(SignatureError):verify_signature("POST","/_proxy/download",headers,body,CREDS)
    def test_expired_and_future_timestamp_rejected(self):
        headers,body=sign()
        for offset in [-3600,3600]:
            now=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=offset)
            with self.assertRaises(SignatureError):verify_signature("POST","/_proxy/download",headers,body,CREDS,now=now)
    def test_bearer_and_missing_auth_rejected(self):
        for value in ["","Bearer old-token","Basic xyz","AWS4-HMAC-SHA256 Credential=x"]:
            with self.assertRaises(SignatureError):
                verify_signature("GET","/_proxy/health",CIMultiDict({"Authorization":value}),b"",CREDS)
    def test_duplicate_signature_headers_rejected(self):
        headers,body=sign();headers.add("X-Amz-Date",headers["X-Amz-Date"])
        with self.assertRaises(SignatureError):verify_signature("POST","/_proxy/download",headers,body,CREDS)
    def test_absent_payload_hash_sdk_variant(self):
        aws=AWSRequest(method="POST",url="https://s3.example.test/_proxy/download",
                       data=b"{}",headers={"Host":"s3.example.test"})
        from botocore.auth import SigV4Auth
        SigV4Auth(Credentials(CREDS["access_key_id"],CREDS["secret_access_key"]),"s3","garage").add_auth(aws)
        verify_signature("POST","/_proxy/download",CIMultiDict(aws.headers.items()),b"{}",CREDS)

if __name__=="__main__":unittest.main(verbosity=2)
