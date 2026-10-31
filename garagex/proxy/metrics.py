"""Bounded sampling of real transfer counters and Linux TCP RTT."""
import contextvars,json,math,pathlib,socket,statistics,struct,time
import aiohttp
CURRENT=contextvars.ContextVar("transfer_trace",default=None)

def tcp_rtt(sock):
    if sock is None or not hasattr(socket,"TCP_INFO"):return None
    try:
        data=sock.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)
        value=struct.unpack_from("=I",data,68)[0]
        return round(value/1000,3) if value else None
    except (OSError,ValueError,AttributeError,struct.error):return None

def source_socket(response):
    connection=getattr(response,"connection",None)
    transport=getattr(connection,"transport",None)
    if transport is None:transport=getattr(getattr(response,"_protocol",None),"transport",None)
    return transport.get_extra_info("socket") if transport else None

def stats(values):
    values=[float(v) for v in values if v is not None and math.isfinite(v)]
    if not values:return {"count":0,"min":None,"mean":None,"p95":None,"max":None}
    values.sort()
    return {"count":len(values),"min":round(values[0],4),"mean":round(statistics.mean(values),4),
            "p95":round(values[min(len(values)-1,math.ceil(len(values)*0.95)-1)],4),"max":round(values[-1],4)}

def trace_config():
    trace=aiohttp.TraceConfig()
    async def dns_start(session,ctx,params):
        record=CURRENT.get()
        if record:ctx.dns_start=time.monotonic()
    async def dns_end(session,ctx,params):
        record=CURRENT.get()
        if record and hasattr(ctx,"dns_start"):
            record.phases["dns_ms"]=record.phases.get("dns_ms",0)+(time.monotonic()-ctx.dns_start)*1000
    async def connect_start(session,ctx,params):
        if CURRENT.get():ctx.connect_start=time.monotonic()
    async def connect_end(session,ctx,params):
        record=CURRENT.get()
        if record and hasattr(ctx,"connect_start"):
            record.phases["connect_dns_tls_ms"]=record.phases.get("connect_dns_tls_ms",0)+(time.monotonic()-ctx.connect_start)*1000
    trace.on_dns_resolvehost_start.append(dns_start);trace.on_dns_resolvehost_end.append(dns_end)
    trace.on_connection_create_start.append(connect_start);trace.on_connection_create_end.append(connect_end)
    return trace

class Meter:
    def __init__(self,path=None):
        self.path=pathlib.Path(path) if path else None
        self.rows=[] if self.path is None else None
        self.started=time.monotonic();self.wall_started=time.time();self.ended=None
        self.received=0;self.sent=0;self.last_received=0;self.last_sent=0;self.last=self.started
        self.sock=None;self.phases={};self.write_wait=0;self.write_count=0
        self.sample_count=0;self.first_byte=False
    def receive(self,n):
        if n and not self.first_byte:
            self.phases["first_body_byte_ms"]=(time.monotonic()-self.started)*1000;self.first_byte=True
        self.received+=n;self.sample()
    def send(self,n,wait_ms=0):
        self.sent+=n;self.write_wait+=wait_ms;self.write_count+=1;self.sample()
    def sample(self,force=False):
        now=time.monotonic();duration=now-self.last
        if not force and duration<1:return
        if duration<=0:return
        row={"elapsed_seconds":round(now-self.started,5),"timestamp":round(self.wall_started+now-self.started,5),
            "upstream_bytes":self.received,"downstream_bytes":self.sent,
            "upstream_mbps":round((self.received-self.last_received)*8/duration/1e6,6),
            "downstream_mbps":round((self.sent-self.last_sent)*8/duration/1e6,6),
            "upstream_tcp_rtt_ms":tcp_rtt(self.sock),
            "downstream_write_wait_ms":round(self.write_wait/self.write_count,4) if self.write_count else None}
        if self.path:
            with self.path.open("a") as stream:stream.write(json.dumps(row)+"\n")
        else:self.rows.append(row)
        self.sample_count+=1
        self.last=now;self.last_received=self.received;self.last_sent=self.sent
        self.write_wait=0;self.write_count=0
    def finish(self):
        self.sample(True);self.ended=time.monotonic()
    def summary(self):
        elapsed=max((self.ended or time.monotonic())-self.started,1e-6)
        return {"duration_seconds":round(elapsed,5),"upstream_bytes":self.received,"downstream_bytes":self.sent,
            "upstream_average_mbps":round(self.received*8/elapsed/1e6,6),
            "downstream_server_write_average_mbps":round(self.sent*8/elapsed/1e6,6),
            "sample_count":self.sample_count,"phases":{k:round(v,4) for k,v in self.phases.items()},
            "latency_definition":"upstream_tcp_rtt_ms is Linux TCP_INFO smoothed RTT; DNS/connect/TTFB include application connection work.",
            "downstream_definition":"Server writes terminate at the reverse proxy. True downstream RTT and receive rates require client observations."}
    def all_rows(self):
        if self.rows is not None:return list(self.rows)
        if not self.path.exists():return []
        rows=[]
        for line in self.path.read_text().splitlines():
            try:rows.append(json.loads(line))
            except ValueError:continue
        return rows

def report_rows(rows,max_points):
    if len(rows)<=max_points:return rows
    result=[];size=math.ceil(len(rows)/max_points)
    previous_time=0;previous_up=0;previous_down=0
    for start in range(0,len(rows),size):
        group=rows[start:start+size];row=dict(group[-1])
        duration=max(row["elapsed_seconds"]-previous_time,1e-6)
        row["upstream_mbps"]=(row["upstream_bytes"]-previous_up)*8/duration/1e6
        row["downstream_mbps"]=(row["downstream_bytes"]-previous_down)*8/duration/1e6
        row["upstream_mbps_peak"]=max(v["upstream_mbps"] for v in group)
        row["downstream_mbps_peak"]=max(v["downstream_mbps"] for v in group)
        rtts=[v["upstream_tcp_rtt_ms"] for v in group if v.get("upstream_tcp_rtt_ms") is not None]
        row["upstream_tcp_rtt_ms"]=statistics.mean(rtts) if rtts else None
        row["upstream_tcp_rtt_peak_ms"]=max(rtts) if rtts else None
        result.append(row)
        previous_time=row["elapsed_seconds"];previous_up=row["upstream_bytes"];previous_down=row["downstream_bytes"]
    return result
