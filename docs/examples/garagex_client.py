#!/usr/bin/env python3
"""External GarageX client. Uses the same S3 credentials for every operation."""
import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import urllib.parse
import urllib.request
import boto3
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.client import Config

@contextlib.contextmanager
def new_output(filename):
    """Publish a complete local file without replacing an existing destination."""
    target=pathlib.Path(filename)
    if target.exists():raise FileExistsError(str(target))
    fd,name=tempfile.mkstemp(prefix=".garagex-",dir=str(target.parent))
    os.close(fd)
    temp=pathlib.Path(name)
    try:
        yield temp
        os.link(temp,target)
    finally:
        temp.unlink(missing_ok=True)

class GarageXClient:
    def __init__(self,endpoint=None,bucket=None,region=None,session=None):
        self.endpoint=(endpoint or os.environ.get("S3_ENDPOINT","https://s3.example.com")).rstrip("/")
        self.bucket=bucket or os.environ.get("S3_BUCKET","garagex")
        self.region=region or os.environ.get("AWS_DEFAULT_REGION","garage")
        self.session=session or boto3.Session(region_name=self.region)
        credentials=self.session.get_credentials()
        if credentials is None:raise RuntimeError("Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.")
        self.credentials=credentials.get_frozen_credentials()
        options=dict(signature_version="s3v4",s3={"addressing_style":"path"},connect_timeout=20,
                     read_timeout=180,retries={"max_attempts":3})
        # Newer AWS SDKs enable optional checksums automatically. Require only the
        # checksums demanded by the operation for S3-compatible endpoints.
        for name in ("request_checksum_calculation","response_checksum_validation"):
            if name in Config.OPTION_DEFAULTS:options[name]="when_required"
        self.s3=self.session.client("s3",endpoint_url=self.endpoint,region_name=self.region,
                                   config=Config(**options))

    def upload(self,filename,key):
        self.s3.upload_file(str(filename),self.bucket,key)
        return {"bucket":self.bucket,"key":key}

    def download(self,key,filename):
        with new_output(filename) as temp:
            self.s3.download_file(self.bucket,key,str(temp))
        return {"bucket":self.bucket,"key":key,"output":str(filename)}

    def objects(self,prefix=""):
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket,Prefix=prefix):
            for item in page.get("Contents",[]):
                yield {"key":item["Key"],"size":item["Size"],"last_modified":item["LastModified"].isoformat()}

    def presign(self,key,expires=3600):
        if not 1<=expires<=604800:raise ValueError("Expiry must be between 1 and 604800 seconds.")
        return self.s3.generate_presigned_url("get_object",Params={"Bucket":self.bucket,"Key":key},ExpiresIn=expires)

    def _request(self,path,payload=None):
        data=json.dumps(payload,ensure_ascii=False).encode("utf-8") if payload is not None else None
        method="POST" if data is not None else "GET"
        aws=AWSRequest(method=method,url=self.endpoint+path,data=data,
                       headers={"Content-Type":"application/json"} if data is not None else {})
        S3SigV4Auth(self.credentials,"s3",self.region).add_auth(aws)
        return urllib.request.Request(aws.url,data=data,method=method,headers=dict(aws.headers.items()))

    def health(self):
        with urllib.request.urlopen(self._request("/_proxy/health"),timeout=30) as response:
            return json.load(response)

    def job(self,job_id):
        with urllib.request.urlopen(self._request("/_proxy/jobs/"+urllib.parse.quote(job_id,safe="")),timeout=30) as response:
            return json.load(response)

    def report(self,job_id,max_points=1000):
        path="/_proxy/jobs/"+urllib.parse.quote(job_id,safe="")+"/report?max_points="+str(max_points)
        with urllib.request.urlopen(self._request(path),timeout=30) as response:return json.load(response)

    def network_test(self,upstream_url=None,byte_count=32*1024**2,seconds=5,report_file=None,report_html=None):
        import time
        result={"kind":"network_test","downstream":{},"upstream":None,"storage_payload_written":False}
        connection=_SignedConnection(self)
        try:
            connection.json("GET","/_proxy/network/ping")
            latencies=[];latency_start=time.monotonic()
            for _ in range(5):
                connection.json("GET","/_proxy/network/ping")
                latencies.append({"elapsed_seconds":time.monotonic()-latency_start,"rtt_ms":connection.last_rtt_ms})
                time.sleep(0.1)
            result["downstream"]["latency"]={"measurement":"HTTP keepalive round trip","rtt_ms":_stats([v["rtt_ms"] for v in latencies]),"timeline":latencies}
            path="/_proxy/network/download?bytes="+str(byte_count)+"&seconds="+str(seconds)
            response=connection.request("GET",path)
            total=0;start=connection.last_start;last=start;last_bytes=0;samples=[]
            while True:
                chunk=response.read(65536)
                if not chunk:break
                total+=len(chunk);now=time.monotonic()
                if now-last>=1:
                    samples.append({"elapsed_seconds":now-start,"received_bytes":total,"mbps":(total-last_bytes)*8/(now-last)/1e6})
                    last=now;last_bytes=total
            now=time.monotonic()
            if now>last:samples.append({"elapsed_seconds":now-start,"received_bytes":total,"mbps":(total-last_bytes)*8/(now-last)/1e6})
            result["downstream"]["download"]={"received_bytes":total,"seconds":now-start,"payload_mbps":total*8/max(now-start,1e-6)/1e6,"timeline":samples}
            body=_PatternStream(byte_count)
            response=connection.request("POST","/_proxy/network/upload",body=body,headers={"Content-Type":"application/octet-stream","Content-Length":str(byte_count)})
            upload=json.load(response);elapsed=time.monotonic()-connection.last_start
            upload["client_elapsed_seconds"]=elapsed;upload["client_payload_mbps"]=byte_count*8/max(elapsed,1e-6)/1e6
            result["downstream"]["upload"]=upload
            if upstream_url is not None:
                response=urllib.request.urlopen(self._request("/_proxy/network/upstream",
                    {"url":upstream_url,"bytes":byte_count,"seconds":seconds}),timeout=180)
                with response:result["upstream"]=json.load(response)
        finally:connection.close()
        _save_report(result,report_file,report_html)
        return result

    def proxy(self,url,filename,key=None,disconnect_mode="continue",retention_seconds=None,
              report_file=None,report_html=None,stop_after_bytes=None):
        import time
        payload={"url":url,"bucket":self.bucket,"disconnect_mode":disconnect_mode,"retention_seconds":retention_seconds}
        if key is not None:payload["key"]=key
        digest=hashlib.sha256();monitor=None;job_id=None;received=0;intentional_stop=False
        with new_output(filename) as temp:
            try:
                with urllib.request.urlopen(self._request("/_proxy/download",payload),timeout=180) as response:
                    job_id=response.headers["X-Download-Id"]
                    print("Download job: "+job_id,file=sys.stderr,flush=True)
                    monitor=_Telemetry(self,job_id,float(response.headers.get("X-Download-Elapsed-Seconds","0")))
                    monitor.start()
                    with temp.open("wb") as output:
                        while True:
                            size=min(65536,stop_after_bytes-received) if stop_after_bytes is not None else 65536
                            if size<=0:intentional_stop=True;break
                            chunk=response.read(size)
                            if not chunk:break
                            output.write(chunk);digest.update(chunk);received+=len(chunk);monitor.received=received
            finally:
                if monitor:monitor.stop()
            deadline=time.monotonic()+60
            result=self.job(job_id)
            while intentional_stop and result["state"] in {"starting","downloading","committing"} and time.monotonic()<deadline:
                time.sleep(0.2);result=self.job(job_id)
            if not intentional_stop and (result["state"]!="completed" or result.get("sha256")!=digest.hexdigest()):
                raise RuntimeError("The proxy job did not complete with the expected SHA-256.")
        if report_file or report_html:_save_report(self.report(job_id),report_file,report_html)
        return result



def _stats(values):
    import math,statistics
    values=sorted(float(v) for v in values if v is not None)
    return {"min":min(values),"mean":statistics.mean(values),"p95":values[max(0,math.ceil(len(values)*0.95)-1)],"max":max(values)} if values else {"min":None,"mean":None,"p95":None,"max":None}

class _PatternStream:
    def __init__(self,size):
        self.size=size;self.position=0;self.pattern=os.urandom(65536)
    def tell(self):return self.position
    def seek(self,offset,whence=0):
        self.position=(offset if whence==0 else self.position+offset if whence==1 else self.size+offset)
        return self.position
    def read(self,n=-1):
        n=min(self.size-self.position,n if n>=0 else 1024*1024)
        if n<=0:return b""
        offset=self.position%len(self.pattern)
        data=(self.pattern*((offset+n)//len(self.pattern)+1))[offset:offset+n]
        self.position+=n;return data

class _SignedConnection:
    def __init__(self,client):
        import http.client
        self.client=client;parsed=urllib.parse.urlsplit(client.endpoint)
        factory=http.client.HTTPSConnection if parsed.scheme=="https" else http.client.HTTPConnection
        self.connection=factory(parsed.hostname,parsed.port,timeout=5)
        self.last_start=0;self.last_rtt_ms=None
    def request(self,method,path,body=None,headers=None):
        import time
        aws=AWSRequest(method=method,url=self.client.endpoint+path,data=body,headers=headers or {})
        S3SigV4Auth(self.client.credentials,"s3",self.client.region).add_auth(aws)
        self.last_start=time.monotonic()
        self.connection.request(method,path,body=body,headers=dict(aws.headers.items()))
        response=self.connection.getresponse()
        if response.status>=400:
            data=response.read().decode(errors="replace")
            raise RuntimeError("Network/telemetry API "+str(response.status)+": "+data[:500])
        return response
    def json(self,method,path,payload=None):
        import time
        body=json.dumps(payload).encode() if payload is not None else None
        response=self.request(method,path,body,{"Content-Type":"application/json"} if body is not None else {})
        result=json.load(response);self.last_rtt_ms=(time.monotonic()-self.last_start)*1000
        return result
    def close(self):self.connection.close()

class _Telemetry:
    def __init__(self,client,ident,offset):
        import threading,time
        self.client=client;self.ident=ident;self.offset=offset;self.started=time.monotonic();self.received=0
        self.event=threading.Event();self.thread=threading.Thread(target=self.run,daemon=True);self.errors=[]
    def start(self):self.thread.start()
    def run(self):
        import time
        connection=_SignedConnection(self.client)
        try:
            connection.json("GET","/_proxy/network/ping")
            while True:
                connection.json("GET","/_proxy/network/ping")
                sample={"elapsed_seconds":self.offset+time.monotonic()-self.started,
                        "received_bytes":self.received,"rtt_ms":connection.last_rtt_ms}
                connection.json("POST","/_proxy/jobs/"+self.ident+"/observations",{"samples":[sample]})
                if self.event.wait(1):
                    connection.json("GET","/_proxy/network/ping")
                    sample={"elapsed_seconds":self.offset+time.monotonic()-self.started,
                            "received_bytes":self.received,"rtt_ms":connection.last_rtt_ms}
                    connection.json("POST","/_proxy/jobs/"+self.ident+"/observations",{"samples":[sample]})
                    break
        except Exception as error:self.errors.append(type(error).__name__)
        finally:connection.close()
    def stop(self):
        self.event.set();self.thread.join(timeout=12)
        if self.thread.is_alive():print("Client telemetry is still stopping; the server-side report remains available.",file=sys.stderr)
        if self.errors:print("Client telemetry unavailable: "+",".join(self.errors),file=sys.stderr)

def _save_report(result,filename=None,html_filename=None):
    if filename:
        with new_output(filename) as temp:temp.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    if html_filename:
        with new_output(html_filename) as temp:temp.write_text(render_report(result))


"""Standalone HTML rendering for latency and throughput reports."""
import html,json,math
def render_report(report):
    proxy="job" in report
    if proxy:
        rows=report.get("timeline",[])
        client=report.get("downstream_client",{}).get("timeline",[])
        rates=[("上游接收",rows,"upstream_mbps"),("服务端向下游写入",rows,"downstream_mbps"),("下游实际接收",client,"receive_mbps")]
        latency=[("上游 TCP SRTT",rows,"upstream_tcp_rtt_ms"),("下游 HTTP RTT",client,"rtt_ms")]
        job=report["job"];title="下载任务 "+job["id"]
        info="状态："+job["state"]+"；对象："+job["bucket"]+"/"+job["key"]+"；部分内容："+str(job.get("is_partial",False))+"；保留期限："+("永久" if job.get("expires_at") is None else str(job["expires_at"]))
    else:
        down=report.get("downstream",{})
        upstream=report.get("upstream") or {}
        rates=[("下游接收",down.get("download",{}).get("timeline",[]),"mbps"),
               ("下游发送",down.get("upload",{}).get("timeline",[]),"upstream_mbps"),
               ("上游到本服务",upstream.get("timeline",[]),"upstream_mbps")]
        latency=[("下游 HTTP RTT",down.get("latency",{}).get("timeline",[]),"rtt_ms"),
                 ("上游 TCP SRTT",upstream.get("timeline",[]),"upstream_tcp_rtt_ms")]
        title="纯网络测试报告";info="测速数据不写入 S3。HTTP RTT 包含应用协议往返；TCP SRTT 来自 Linux 内核。"
    colors=["#1765b4","#c64c35","#168568"]
    def chart(label,series,unit):
        normalized=[]
        for name,rows,field in series:
            points=[]
            for row in rows:
                x=row.get("elapsed_seconds");y=row.get(field)
                if isinstance(x,(int,float)) and isinstance(y,(int,float)) and math.isfinite(x) and math.isfinite(y):
                    points.append((x,y))
            if points:normalized.append((name,points))
        if not normalized:return "<h2>"+label+"</h2><p>没有该指标的可用测量；未将不可用数据填为零。</p>"
        xmax=max(1,max(x for _,points in normalized for x,y in points));ymax=max(1,max(y for _,points in normalized for x,y in points)*1.1)
        elements=[]
        for i in range(6):
            y=230-i*38
            elements.append(f'<line x1="68" y1="{y}" x2="820" y2="{y}" stroke="#dde5ee"/><text x="60" y="{y+4}" text-anchor="end">{ymax*i/5:.2f}</text>')
            x=68+i*150.4
            elements.append(f'<text x="{x}" y="255" text-anchor="middle">{xmax*i/5:.1f}</text>')
        legend=[]
        for i,(name,points) in enumerate(normalized):
            color=colors[i%len(colors)]
            coords=" ".join(f"{68+x/xmax*752:.2f},{230-y/ymax*190:.2f}" for x,y in points)
            elements.append(f'<polyline points="{coords}" fill="none" stroke="{color}" stroke-width="2.2"/>')
            if len(points)==1:
                x,y=points[0];elements.append(f'<circle cx="{68+x/xmax*752}" cy="{230-y/ymax*190}" r="3" fill="{color}"/>')
            legend.append(f'<span style="color:{color}">● {html.escape(name)}</span>')
        return '<h2>'+label+'</h2><div class="legend">'+" ".join(legend)+f'</div><svg viewBox="0 0 850 285" role="img" aria-label="{label}"><text x="8" y="20">{unit}</text>'+"".join(elements)+'<text x="780" y="280">秒</text></svg>'
    return '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+html.escape(title)+'''</title><style>body{font:16px/1.7 system-ui,sans-serif;color:#193044;max-width:1000px;margin:36px auto;padding:0 22px;background:#f8fafc}h1{font-size:27px}h2{font-size:21px;margin-top:30px}svg{background:white;border:1px solid #dce4ed;border-radius:7px;width:100%}svg text{font:12px system-ui;fill:#465f75}.legend{display:flex;gap:20px;flex-wrap:wrap;font-size:14px;margin:12px 0}pre{overflow:auto;padding:18px;background:#102737;color:#e4eef7;border-radius:7px;font-size:12px}summary{cursor:pointer}p{overflow-wrap:anywhere}</style><h1>'''+html.escape(title)+'</h1><p>'+html.escape(info)+'</p>'+chart("吞吐率变化",rates,"Mbps")+chart("延迟变化",latency,"ms")+'<p>代理的服务端写出速率不是客户端实际接收速率。下游真实指标由客户端测量并上报；无客户端观测时该序列为空。长任务报告可能下采样，完整采样统计仍保留在摘要中。</p><details><summary>完整 JSON 数据</summary><pre>'+html.escape(json.dumps(report,indent=2,ensure_ascii=False))+'</pre></details></html>'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="operation",required=True)
    upload=sub.add_parser("upload");upload.add_argument("file");upload.add_argument("key")
    download=sub.add_parser("download");download.add_argument("key");download.add_argument("-o","--output",required=True)
    listing=sub.add_parser("ls");listing.add_argument("prefix",nargs="?",default="")
    presign=sub.add_parser("presign");presign.add_argument("key");presign.add_argument("--expires",type=int,default=3600)
    proxy=sub.add_parser("proxy");proxy.add_argument("url");proxy.add_argument("-o","--output",required=True);proxy.add_argument("--key");proxy.add_argument("--disconnect-mode",choices=["continue","stop_keep"],default="continue");proxy.add_argument("--retention-seconds",type=int);proxy.add_argument("--stop-after-bytes",type=int);proxy.add_argument("--report");proxy.add_argument("--report-html")
    job=sub.add_parser("job");job.add_argument("id")
    report=sub.add_parser("report");report.add_argument("id");report.add_argument("-o","--output");report.add_argument("--html")
    network=sub.add_parser("network-test");network.add_argument("--upstream");network.add_argument("--bytes",type=int,default=33554432);network.add_argument("--seconds",type=float,default=5);network.add_argument("--report");network.add_argument("--report-html")
    sub.add_parser("health")
    args=parser.parse_args();client=GarageXClient()
    if args.operation=="upload":result=client.upload(args.file,args.key)
    elif args.operation=="download":result=client.download(args.key,args.output)
    elif args.operation=="proxy":result=client.proxy(args.url,args.output,args.key,args.disconnect_mode,args.retention_seconds,args.report,args.report_html,args.stop_after_bytes)
    elif args.operation=="job":result=client.job(args.id)
    elif args.operation=="network-test":result=client.network_test(args.upstream,args.bytes,args.seconds,args.report,args.report_html)
    elif args.operation=="report":
        result=client.report(args.id);_save_report(result,args.output,args.html)
    elif args.operation=="health":result=client.health()
    elif args.operation=="presign":
        print(client.presign(args.key,args.expires));return
    else:
        for item in client.objects(args.prefix):print(json.dumps(item,ensure_ascii=False))
        return
    print(json.dumps(result,indent=2,ensure_ascii=False))
if __name__=="__main__":main()
