import {test} from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {createRequire} from "node:module";
import {webcrypto,randomUUID} from "node:crypto";
import {signRequest} from "../../garagex/admin/static/sigv4.mjs";
const require=createRequire(import.meta.url),{JSDOM,VirtualConsole}=require("jsdom");if(!globalThis.crypto?.subtle)Object.defineProperty(globalThis,"crypto",{value:webcrypto,configurable:true});
const html=await readFile(new URL("../../garagex/admin/static/index.html",import.meta.url),"utf8");
const source=(await readFile(new URL("../../garagex/admin/static/app.js",import.meta.url),"utf8")).replace(/^import .*;\n/,"");
const bucket={id:"c".repeat(64),aliases:["t-customer-files"],keys:[],bytes:12,objects:1,quotas:{maxSize:1024**3}};
const wait=async(predicate)=>{for(let i=0;i<200;i++){if(predicate())return;await new Promise(r=>setTimeout(r,10));}throw new Error("UI state timed out");};
function harness(role="platform",hash="#buckets"){
 const dom=new JSDOM(html,{url:"https://s3.example.com/admin/"+hash,runScripts:"outside-only",pretendToBeVisual:true,virtualConsole:new VirtualConsole()});
 const w=dom.window,$=id=>w.document.getElementById(id),calls=[];
 Object.defineProperty(w.crypto,"subtle",{value:webcrypto.subtle});w.crypto.randomUUID=randomUUID;w.TextEncoder=TextEncoder;w.AbortController=AbortController;w.signRequest=signRequest;w.confirm=()=>true;
 w.HTMLDialogElement.prototype.showModal=function(){this.setAttribute("open","");};
 w.HTMLDialogElement.prototype.close=function(){this.removeAttribute("open");this.dispatchEvent(new w.Event("close"));};
 w.fetch=async(url,options)=>{
  const path=new URL(url).pathname.replace("/admin/api",""),payload=options.body?JSON.parse(options.body):undefined;calls.push({path,payload});
  let data={};
  if(path==="/session")data={endpoint:"https://s3.example.com",region:"garage",role,tenant:{name:"Customer",prefix:"t-customer-"}};
  else if(path==="/keys")data={items:[{accessKeyId:"TEST_OWNER",name:"Owner",role:"owner",buckets:[]}],nextCursor:null};
  else if(path==="/buckets")data=options.method==="POST"?{bucket:{...bucket,aliases:["t-customer-"+payload.name]}}:{items:[bucket]};
  else if(path==="/tenants")data=options.method==="POST"?{tenant:{name:payload.name},credentials:{access_key_id:"TEST_NEW_OWNER",secret_access_key:"test-only-secret"}}:{items:[]};
  else if(path==="/usage")data={tenant:{quota_bytes:10*1024**3,max_buckets:10,max_keys:10,max_concurrent:2},allocated_bytes:1024**3,used_bytes:12,bucket_count:1,key_count:1,objects:1};
  else if(path==="/objects")data={bucket:{id:bucket.id,name:bucket.aliases[0]},directories:[],items:[{key:"folder/<script>%literal.html",size:12}],nextCursor:null};
  else if(path==="/objects/detail")data={bucket:{id:bucket.id},key:"folder/<script>%literal.html",size:12,contentType:"text/html",textPreview:true,imagePreview:false};
  else if(path==="/objects/preview")data={text:"<script>window.infected=true</script>",truncated:false};
  else if(path==="/objects/link")data={url:"/admin/download/test-ticket"};
  return {ok:true,status:200,json:async()=>data};
 };
 w.eval(source);
 const submit=id=>$(id).dispatchEvent(new w.Event("submit",{bubbles:true,cancelable:true}));
 return {w,$,calls,submit,close:()=>w.close(),login:async()=>{$("login-access").value="TEST_OWNER";$("login-secret").value="test-only-secret";submit("login-form");await wait(()=>!$("console-view").hidden&&$("bucket-rows").children.length);}};
}
test("platform opens customer and clears initial secret when dialog closes",async()=>{
 const h=harness();try{
  await h.login();assert.equal(h.$("nav-tenants").hidden,false);assert.equal(h.$("nav-usage").hidden,true);
  h.$("nav-tenants").click();await wait(()=>!h.$("tenants-view").hidden);
  h.$("open-tenant").click();h.$("tenant-name").value="Customer A";h.submit("tenant-form");
  await wait(()=>h.$("detail-dialog").open&&h.$("detail-secret").value&&!h.$("tenant-submit").disabled);
  assert.equal(h.$("detail-access").value,"TEST_NEW_OWNER");assert.equal(h.$("detail-secret").value,"test-only-secret");
  h.$("detail-dialog").close();assert.equal(h.$("detail-secret").value,"");
  h.$("logout").click();assert.equal(h.$("login-view").hidden,false);assert.equal(h.$("login-secret").value,"");
 }finally{h.close();}
});
test("tenant sees own usage and creates bucket with allocation cap",async()=>{
 const h=harness("tenant");try{
  await h.login();assert.equal(h.$("nav-tenants").hidden,true);assert.equal(h.$("nav-usage").hidden,false);
  h.$("nav-usage").click();await wait(()=>h.$("usage-counts").textContent==="1 / 1");
  h.$("nav-buckets").click();h.$("open-create-bucket").click();assert.equal(h.$("bucket-quota-field").hidden,false);
  h.$("bucket-name").value="backups";h.$("bucket-quota").value="2";h.submit("bucket-create-form");
  await wait(()=>h.$("bucket-detail-dialog").open&&!h.$("bucket-create-submit").disabled);
  assert.equal(h.calls.find(x=>x.path==="/buckets"&&x.payload).payload.quota_bytes,2*1024**3);
 }finally{h.close();}
});
test("bucket browser renders keys safely and previews active content only as text",async()=>{
 const h=harness("tenant");try{
  await h.login();h.$("bucket-rows").querySelector("button").click();await wait(()=>h.$("object-rows").children.length);
  assert.equal(h.$("objects-view").hidden,false);assert.equal(h.$("object-rows").querySelector("script"),null);
  h.$("object-rows").querySelector("button").click();await wait(()=>!h.$("object-preview").hidden);h.$("object-preview").click();
  await wait(()=>!h.$("object-text").hidden);assert.match(h.$("object-text").textContent,/<script>/);assert.equal(h.w.infected,undefined);
  h.$("object-dialog").close();assert.equal(h.$("object-text").textContent,"");assert.equal(h.$("object-image").hasAttribute("src"),false);
 }finally{h.close();}
});
