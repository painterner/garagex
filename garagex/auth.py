"""S3 SigV4 signing and verification using the existing S3 credential pair."""
import datetime
import hashlib
import hmac
import json
import pathlib
import re
import urllib.request
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

class SignatureError(Exception):
    pass

def load_credentials(path="/etc/garagex/credentials.json"):
    return json.loads(pathlib.Path(path).read_text())

def signed_request(credentials,url,data=None,method=None,headers=None):
    method=method or ("POST" if data is not None else "GET")
    aws=AWSRequest(method=method,url=url,data=data,headers=headers or {})
    S3SigV4Auth(Credentials(credentials["access_key_id"],credentials["secret_access_key"]),
               "s3",credentials["region"]).add_auth(aws)
    return urllib.request.Request(url,data=data,method=method,headers=dict(aws.headers.items()))

def verify_signature(method,raw_path,headers,body,credentials,now=None):
    authorization=headers.get("Authorization","")
    if not authorization.startswith("AWS4-HMAC-SHA256 "):
        raise SignatureError("S3 SigV4 authentication is required.")
    try:
        fields={}
        for item in authorization[len("AWS4-HMAC-SHA256 "):].split(","):
            key,value=item.strip().split("=",1)
            if key in fields: raise ValueError()
            fields[key]=value
        if set(fields)!={"Credential","SignedHeaders","Signature"}: raise ValueError()
        access,date,region,service,end=fields["Credential"].split("/")
        names=fields["SignedHeaders"].split(";")
        timestamp=headers["X-Amz-Date"]
        when=datetime.datetime.strptime(timestamp,"%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
        if (not re.fullmatch(r"[A-Za-z0-9]+",access) or
                not re.fullmatch(r"[a-fA-F0-9]{64}",fields["Signature"]) or
                names!=sorted(set(names)) or
                not {"host","x-amz-date"}.issubset(names) or
                "authorization" in names or
                any(not re.fullmatch(r"[a-z0-9-]+",n) for n in names) or
                date!=timestamp[:8] or region!=credentials["region"] or service!="s3" or end!="aws4_request"):
            raise ValueError()
        current=now or datetime.datetime.now(datetime.timezone.utc)
        if abs((current-when).total_seconds())>900:
            raise SignatureError("The S3 request timestamp has expired or is too far in the future.")
        if not hmac.compare_digest(access.encode(),credentials["access_key_id"].encode()):
            raise SignatureError("Invalid S3 credentials or signature.")
        for name in ["Authorization","X-Amz-Date","Host","X-Amz-Content-SHA256"]:
            if hasattr(headers,"getall") and len(headers.getall(name,[]))>1: raise ValueError()
        supplied_hash=headers.get("X-Amz-Content-SHA256")
        if body is None:
            if supplied_hash is None or not re.fullmatch(r"[0-9a-f]{64}",supplied_hash) or "x-amz-content-sha256" not in names:
                raise SignatureError("A signed SHA-256 header is required for a streaming network upload.")
            expected_hash=supplied_hash
        else:
            expected_hash=hashlib.sha256(body).hexdigest()
        if supplied_hash is not None and not hmac.compare_digest(supplied_hash,expected_hash):
            raise SignatureError("The signed payload hash does not match the request body.")
        aws=AWSRequest(method=method,url="https://"+headers["Host"]+raw_path,data=body)
        for name in names:
            values=headers.getall(name,[]) if hasattr(headers,"getall") else ([headers[name]] if name in headers else [])
            if not values: raise ValueError()
            for value in values: aws.headers.add_header(name,value)
        aws.context["timestamp"]=timestamp
        signer=S3SigV4Auth(Credentials(credentials["access_key_id"],credentials["secret_access_key"]),"s3",region)
        canonical=signer.canonical_request(aws)
        if signer.signed_headers(signer.headers_to_sign(aws))!=fields["SignedHeaders"]: raise ValueError()
        expected=signer.signature(signer.string_to_sign(aws,canonical),aws)
        if not hmac.compare_digest(expected,fields["Signature"].lower()):
            raise SignatureError("Invalid S3 credentials or signature.")
    except SignatureError: raise
    except (ValueError,KeyError,TypeError,UnicodeError):
        raise SignatureError("Malformed S3 SigV4 authentication.")
