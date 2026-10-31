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
