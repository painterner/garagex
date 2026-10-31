const encoder=new TextEncoder();
const hex=value=>Array.from(new Uint8Array(value),b=>b.toString(16).padStart(2,"0")).join("");
const encode=value=>encodeURIComponent(value).replace(/[!'()*]/g,c=>"%"+c.charCodeAt(0).toString(16).toUpperCase());
async function hash(value){return hex(await crypto.subtle.digest("SHA-256",encoder.encode(value)));}
async function hmac(key,value){
  const imported=await crypto.subtle.importKey("raw",typeof key==="string"?encoder.encode(key):key,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return crypto.subtle.sign("HMAC",imported,encoder.encode(value));
}
export async function signRequest({url,method="GET",body="",accessKeyId,secretAccessKey,region="garage",now=new Date()}){
  const target=new URL(url),timestamp=now.toISOString().replace(/[:-]|\.\d{3}/g,""),date=timestamp.slice(0,8);
  const payloadHash=await hash(body),scope=date+"/"+region+"/s3/aws4_request";
  const query=Array.from(target.searchParams,([k,v])=>[encode(k),encode(v)]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:a[1]<b[1]?-1:a[1]>b[1]?1:0).map(([k,v])=>k+"="+v).join("&");
  const names="host;x-amz-content-sha256;x-amz-date";
  const canonical=[method,target.pathname,query,"host:"+target.host+"\nx-amz-content-sha256:"+payloadHash+"\nx-amz-date:"+timestamp+"\n",names,payloadHash].join("\n");
  const stringToSign=["AWS4-HMAC-SHA256",timestamp,scope,await hash(canonical)].join("\n");
  const key=await hmac(await hmac(await hmac(await hmac("AWS4"+secretAccessKey,date),region),"s3"),"aws4_request");
  return {"X-Amz-Date":timestamp,"X-Amz-Content-SHA256":payloadHash,
    "Authorization":"AWS4-HMAC-SHA256 Credential="+accessKeyId+"/"+scope+", SignedHeaders="+names+", Signature="+hex(await hmac(key,stringToSign))};
}
