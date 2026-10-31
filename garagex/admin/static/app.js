import {signRequest} from "./sigv4.mjs";
const $=id=>document.getElementById(id);
let credentials=null,metadata=null,keys=[],buckets=[],authenticated=false,generation=0;
let cursor=null,nextCursor=null,previousCursors=[],currentKey=null,secretTimer=null,toastTimer=null;
let creating=false,pendingCreate=null,refreshing=false,refreshQueued=false;
let bucketCreating=false,pendingBucket=null,currentBucket=null,currentView="keys";
function showError(id,message){$(id).textContent=message;$(id).hidden=!message;}
function toast(message){clearTimeout(toastTimer);$("toast").textContent=message;$("toast").hidden=false;toastTimer=setTimeout(()=>$("toast").hidden=true,3500);}
function clearSecret(){
  clearTimeout(secretTimer);$("detail-secret").value="";$("detail-secret").type="password";
  $("reveal-secret").textContent="显示";$("copy-secret").disabled=true;$("download-credentials").disabled=true;
}
function showSecret(secret){
  clearSecret();$("detail-secret").value=secret;$("detail-secret").type="text";
  $("reveal-secret").textContent="隐藏";$("copy-secret").disabled=false;$("download-credentials").disabled=false;
  secretTimer=setTimeout(clearSecret,60000);
}
function logout(){
  objectEpoch++;objectState=null;tenants=[];pendingTenant=null;clearObject();$("tenant-rows").replaceChildren();$("object-rows").replaceChildren();
  generation++;credentials=null;metadata=null;authenticated=false;keys=[];buckets=[];currentKey=null;pendingCreate=null;currentBucket=null;pendingBucket=null;refreshQueued=false;
  clearSecret();for(const dialog of document.querySelectorAll("dialog"))if(dialog.open)dialog.close();
  $("bucket-rows").replaceChildren();$("bucket-detail-keys").replaceChildren();$("bucket-detail-id").value="";$("bucket-detail-uri").value="";
  $("key-rows").replaceChildren();$("bucket-grants").replaceChildren();$("detail-grants").replaceChildren();
  $("detail-access").value="";$("detail-title").textContent="密钥详情";$("detail-status").textContent="";
  $("login-form").reset();$("create-form").reset();$("bucket-create-form").reset();$("console-view").hidden=true;$("login-view").hidden=false;
  cursor=null;nextCursor=null;previousCursors=[];$("login-access").focus();
}
async function api(path,{method="GET",payload}={}){
  if(!credentials)throw new Error("请先登录。");
  const epoch=generation,url=location.origin+"/admin/api"+path,body=payload===undefined?"":JSON.stringify(payload);
  const headers=await signRequest({url,method,body,...credentials});
  if(payload!==undefined)headers["Content-Type"]="application/json";
  const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),60000);
  let response;
  try{response=await fetch(url,{method,headers,body:method==="GET"?undefined:body,cache:"no-store",credentials:"omit",signal:controller.signal});}
  catch(error){throw new Error(method==="POST"?"请求状态不确定，请刷新列表检查结果后再决定是否重试。":"无法连接管理服务，请检查网络后重试。");}
  finally{clearTimeout(timeout);}
  if(epoch!==generation)throw new Error("本次登录已结束。");
  let result;
  try{result=await response.json();}catch{throw new Error("管理服务返回了无法读取的响应。");}
  if(!response.ok){
    if(response.status===401&&authenticated){logout();toast("登录验证失败，请重新登录。");}
    throw new Error(result.error?.message||"请求失败（"+response.status+"）。");
  }
  return result;
}
function element(tag,text,className){
  const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;
}
function date(value){return value?new Intl.DateTimeFormat("zh-CN",{year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false}).format(new Date(value)):"—";}
function permissionRows(items){
  const fragment=document.createDocumentFragment();
  for(const bucket of items||[]){
    const permissions=bucket.permissions||{},row=element("div",undefined,"permission-row");
    const name=(bucket.globalAliases||[])[0]||bucket.id.slice(0,12)+"…",code=element("code",name);code.title=bucket.id;row.append(code);
    const labels=[permissions.read&&"读",permissions.write&&"写",permissions.owner&&"管理"].filter(Boolean);
    row.append(element("span",labels.join(" · ")||"无权限"));fragment.append(row);
  }
  if(!fragment.childNodes.length)fragment.append(element("span","未授权任何桶","muted small"));
  return fragment;
}
function renderKeys(){
  const search=$("search").value.trim().toLowerCase(),rows=$("key-rows");rows.replaceChildren();
  const filtered=keys.filter(key=>(key.name+" "+key.accessKeyId).toLowerCase().includes(search));
  for(const key of filtered){
    const row=element("tr"),identity=element("td"),name=element("div",key.name||"未命名密钥","key-name");
    if(key.isAdmin||key.role==="owner")name.append(element("span","管理登录","admin-tag"));
    identity.append(name,element("div",key.accessKeyId,"key-id"));row.append(identity);
    const grants=element("td");grants.append(permissionRows(key.buckets));row.append(grants);
    const status=element("td");status.append(element("span",key.expired?"已过期":"有效","badge"+(key.expired?" expired":"")));row.append(status);
    row.append(element("td",date(key.created),"muted"));
    const action=element("td"),button=element("button","查看详情","row-button");button.type="button";button.setAttribute("aria-label","查看 "+(key.name||key.accessKeyId)+" 的密钥详情");
    button.addEventListener("click",()=>openDetails(key));action.append(button);row.append(action);rows.append(row);
  }
  $("list-empty").hidden=filtered.length!==0;$("list-empty").textContent=search?"当前页没有匹配的密钥。":"尚未创建访问密钥。";
  $("key-count").textContent=String(keys.length);$("list-caption").textContent="本页 "+keys.length+" 个密钥"+(search?" · 匹配 "+filtered.length+" 个":"");
  $("previous").disabled=previousCursors.length===0;$("next").disabled=!nextCursor;
  $("page-number").textContent=String(previousCursors.length+1);
}
async function refresh(){
  if(refreshing){refreshQueued=true;return;}
  refreshing=true;$("refresh").disabled=true;showError("page-error","");showError("bucket-page-error","");$("refresh-buckets").disabled=true;$("bucket-list-caption").textContent="正在加载…";$("list-caption").textContent="正在加载…";
  const epoch=generation;
  try{
    const query=cursor?"?offset="+encodeURIComponent(cursor):"";
    const [keyData,bucketData]=await Promise.all([api("/keys"+query),api("/buckets")]);
    if(epoch!==generation)return;
    keys=keyData.items;nextCursor=keyData.nextCursor;buckets=bucketData.items;
    $("bucket-count").textContent=String(buckets.length);renderKeys();renderBuckets();$("open-create").disabled=buckets.length===0;
  }catch(error){if(authenticated){showError("page-error",error.message);showError("bucket-page-error",error.message);$("bucket-list-caption").textContent="加载失败，点击刷新重试。";$("list-caption").textContent="加载失败，点击刷新重试。";}}
  finally{
    refreshing=false;$("refresh").disabled=false;$("refresh-buckets").disabled=false;
    if(refreshQueued){refreshQueued=false;if(authenticated)await refresh();}
  }
}
function openDetails(key,secret=null){
  currentKey=key;clearSecret();showError("detail-error","");$("detail-title").textContent=key.name||"未命名密钥";
  $("detail-access").value=key.accessKeyId;
  $("detail-status").textContent=(secret?"密钥已创建。请复制或下载保存。":"创建于 "+date(key.created))+" · "+(key.expiration?"到期："+date(key.expiration):"永不过期");
  $("detail-grants").replaceChildren(permissionRows(key.buckets));
  $("revoke-key").hidden=key.role!=="app";
  $("detail-dialog").showModal();if(secret)showSecret(secret);
}
function openCreate(selectedBucket=null){
  pendingCreate=null;$("create-form").reset();showError("create-error","");const container=$("bucket-grants");container.replaceChildren();
  for(const bucket of buckets){
    const row=element("div",undefined,"bucket-grant"),name=element("code",bucket.aliases[0]||bucket.id.slice(0,16)+"…");
    name.title=bucket.id;row.append(name);const choices=element("div",undefined,"bucket-options");
    for(const [field,label] of [["read","读"],["write","写"]]){
      const wrapper=element("label"),checkbox=element("input");checkbox.type="checkbox";checkbox.dataset.bucket=bucket.id;checkbox.dataset.permission=field;
      checkbox.checked=selectedBucket?bucket.id===selectedBucket:bucket.aliases.includes(metadata.defaultBucket);wrapper.append(checkbox,document.createTextNode(label));choices.append(wrapper);
    }
    row.append(choices);container.append(row);
  }
  $("create-dialog").showModal();
}
async function copyField(id){
  const field=$(id);
  try{await navigator.clipboard.writeText(field.value);toast("已复制。");}
  catch{field.focus();field.select();toast("无法自动复制，请手动复制所选内容。");}
}
$("login-form").addEventListener("submit",async event=>{
  event.preventDefault();showError("login-error","");$("login-submit").disabled=true;
  credentials={accessKeyId:$("login-access").value.trim(),secretAccessKey:$("login-secret").value.trim()};
  if(!globalThis.crypto?.subtle){showError("login-error","此浏览器无法使用安全签名，请使用支持 WebCrypto 的现代浏览器并通过 HTTPS 访问。");credentials=null;$("login-submit").disabled=false;return;}
  try{
    metadata=await api("/session");authenticated=true;$("login-secret").value="";
    $("endpoint").textContent=new URL(metadata.endpoint).host;$("region").textContent=metadata.region;
    $("login-view").hidden=true;$("console-view").hidden=false;
    configureRole();await refresh();route();
  }catch(error){credentials=null;$("login-secret").value="";showError("login-error",error.message);}
  finally{$("login-submit").disabled=false;}
});
$("logout").addEventListener("click",logout);
$("refresh").addEventListener("click",refresh);
$("search").addEventListener("input",renderKeys);
$("open-create").addEventListener("click",()=>openCreate());
$("next").addEventListener("click",()=>{if(nextCursor&&!refreshing){previousCursors.push(cursor);cursor=nextCursor;$("search").value="";refresh();}});
$("previous").addEventListener("click",()=>{if(previousCursors.length&&!refreshing){cursor=previousCursors.pop();$("search").value="";refresh();}});
document.querySelectorAll("[data-close]").forEach(button=>button.addEventListener("click",()=>$(button.dataset.close).close()));
$("detail-dialog").addEventListener("close",()=>{clearSecret();currentKey=null;});
$("create-dialog").addEventListener("cancel",event=>{if(creating)event.preventDefault();});
$("create-form").addEventListener("submit",async event=>{
  event.preventDefault();if(creating)return;showError("create-error","");
  const grants=buckets.map(bucket=>{
    const boxes=Array.from($("bucket-grants").querySelectorAll("input")).filter(input=>input.dataset.bucket===bucket.id);
    return {bucketId:bucket.id,read:boxes.find(input=>input.dataset.permission==="read").checked,write:boxes.find(input=>input.dataset.permission==="write").checked};
  }).filter(grant=>grant.read||grant.write);
  if(!grants.length){showError("create-error","请至少选择一个桶的读或写权限。");return;}
  const payload={name:$("key-name").value.trim(),grants},fingerprint=JSON.stringify(payload);
  if(!pendingCreate||pendingCreate.fingerprint!==fingerprint)pendingCreate={fingerprint,id:crypto.randomUUID()};
  payload.request_id=pendingCreate.id;
  creating=true;const epoch=generation;$("create-submit").textContent="正在创建…";
  $("create-form").querySelectorAll("button,input").forEach(input=>input.disabled=true);
  try{
    const result=await api("/keys",{method:"POST",payload});
    if(epoch!==generation)return;
    $("create-dialog").close();pendingCreate=null;openDetails(result.key,result.secretAccessKey);
    toast("访问密钥已创建。");cursor=null;previousCursors=[];$("search").value="";await refresh();
  }catch(error){if(epoch===generation)showError("create-error",error.message);}
  finally{creating=false;$("create-submit").textContent="创建密钥";$("create-form").querySelectorAll("button,input").forEach(input=>input.disabled=false);}
});
$("reveal-secret").addEventListener("click",async()=>{
  if($("detail-secret").value){clearSecret();return;}
  const key=currentKey;if(!key)return;$("reveal-secret").disabled=true;showError("detail-error","");
  try{
    const result=await api("/keys/"+key.accessKeyId+"/reveal",{method:"POST",payload:{}});
    if($("detail-dialog").open&&currentKey?.accessKeyId===key.accessKeyId)showSecret(result.secretAccessKey);
  }catch(error){showError("detail-error",error.message);}
  finally{$("reveal-secret").disabled=false;}
});
$("copy-access").addEventListener("click",()=>copyField("detail-access"));
$("copy-secret").addEventListener("click",()=>copyField("detail-secret"));
$("download-credentials").addEventListener("click",()=>{
  if(!currentKey||!$("detail-secret").value)return;
  const value={endpoint:metadata.endpoint,region:metadata.region,bucket:currentKey.credentialBucket??(currentKey.buckets?.[0]?.globalAliases?.[0]||metadata.defaultBucket),
    access_key_id:currentKey.accessKeyId,secret_access_key:$("detail-secret").value};
  const blob=new Blob([JSON.stringify(value,null,2)+"\n"],{type:"application/json"}),url=URL.createObjectURL(blob);
  const link=element("a");link.href=url;link.download="s3-credentials-"+currentKey.accessKeyId+".json";link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);toast("凭据文件包含 Secret Key，请妥善保存。");
});
window.addEventListener("pagehide",()=>{credentials=null;clearSecret();$("login-secret").value="";});

window.addEventListener("pageshow",event=>{if(event.persisted)logout();});

document.addEventListener("visibilitychange",()=>{if(document.hidden)clearSecret();});

function setView(view){
  currentView=view;
  for(const page of ["keys","buckets","tenants","usage","objects"]){
    $(page+"-view").hidden=page!==view;
    const link=$("nav-"+page);if(link){link.classList.toggle("active",page===view);if(page===view)link.setAttribute("aria-current","page");else link.removeAttribute("aria-current");}
  }
  $("current-page").textContent=({keys:"访问密钥",buckets:"存储桶",tenants:"客户租户",usage:"用量与配额",objects:"桶内文件"})[view];
  document.title=$("current-page").textContent+" · GarageX";
}

function formatBytes(value){
  const size=Math.max(0,Number(value)||0);if(size<1024)return size+" B";
  const unit=Math.min(5,Math.floor(Math.log(size)/Math.log(1024)));
  return (size/1024**unit).toLocaleString("zh-CN",{maximumFractionDigits:2})+" "+["B","KiB","MiB","GiB","TiB","PiB"][unit];
}
function renderBuckets(){
  const query=$("bucket-search").value.trim().toLowerCase(),rows=$("bucket-rows");rows.replaceChildren();
  const filtered=buckets.filter(bucket=>(bucket.aliases.join(" ")+" "+bucket.id).toLowerCase().includes(query));
  for(const bucket of filtered){
    const row=element("tr"),identity=element("td");
    identity.append(element("div",bucket.aliases[0]||"无全局别名","key-name"),element("div",bucket.id.slice(0,20)+"…","key-id"));
    row.append(identity,element("td",(bucket.objects||0).toLocaleString("zh-CN")),element("td",formatBytes(bucket.bytes)),
      element("td",String(bucket.keys?.length||0)),element("td",date(bucket.created),"muted"));
    const action=element("td"),button=element("button","查看详情","row-button");
    button.type="button";button.setAttribute("aria-label","查看 "+(bucket.aliases[0]||bucket.id)+" 存储桶详情");
    const browse=element("button","浏览文件","row-button");browse.type="button";browse.addEventListener("click",()=>navigateObjects(bucket.id));
    button.addEventListener("click",()=>openBucketDetails(bucket));action.append(browse,button);row.append(action);rows.append(row);
  }
  $("storage-bucket-count").textContent=String(buckets.length);
  $("storage-object-count").textContent=buckets.reduce((sum,b)=>sum+(b.objects||0),0).toLocaleString("zh-CN");
  $("storage-bytes").textContent=formatBytes(buckets.reduce((sum,b)=>sum+(b.bytes||0),0));
  $("bucket-list-caption").textContent="共 "+buckets.length+" 个存储桶"+(query?" · 匹配 "+filtered.length+" 个":"");
  $("bucket-list-empty").hidden=filtered.length!==0;$("bucket-list-empty").textContent=query?"没有匹配的存储桶。":"尚未创建存储桶。";
}
function openBucketDetails(bucket){
  currentBucket=bucket;$("bucket-detail-title").textContent=bucket.aliases[0]||"无全局别名";
  $("bucket-detail-created").textContent="创建于 "+date(bucket.created)+" · 私有访问";
  $("bucket-detail-id").value=bucket.id;$("bucket-detail-uri").value="s3://"+(bucket.aliases[0]||bucket.id)+"/";
  $("bucket-detail-objects").textContent=(bucket.objects||0).toLocaleString("zh-CN");
  $("bucket-detail-bytes").textContent=formatBytes(bucket.bytes);
  $("bucket-detail-uploads").textContent=String(bucket.unfinishedUploads||0);
  $("bucket-detail-quota").textContent=bucket.quotas?.maxSize==null?"不限":formatBytes(bucket.quotas.maxSize);
  $("bucket-detail-multipart").textContent=String(bucket.unfinishedMultipartUploads||0);
  $("bucket-detail-object-quota").textContent=bucket.quotas?.maxObjects==null?"不限":bucket.quotas.maxObjects.toLocaleString("zh-CN");
  const container=$("bucket-detail-keys");container.replaceChildren();
  for(const key of bucket.keys||[]){
    const row=element("div",undefined,"bucket-key-row"),identity=element("div");
    const name=element("div",key.name||"未命名密钥","key-name");if(key.isAdmin||key.role==="owner")name.append(element("span","管理登录","admin-tag"));
    identity.append(name,element("div",key.accessKeyId,"key-id"));
    const labels=["read","write","owner"].filter(p=>key.permissions[p]).map(p=>({read:"读",write:"写",owner:"管理"})[p]);
    row.append(identity,element("span",labels.join(" · ")||"无权限","muted small"));container.append(row);
  }
  if(!container.children.length)container.append(element("p","未授权任何密钥。","muted small"));
  $("bucket-detail-dialog").showModal();
}
window.addEventListener("hashchange",()=>{if(authenticated)route();});
$("bucket-search").addEventListener("input",renderBuckets);
$("refresh-buckets").addEventListener("click",refresh);
$("copy-bucket-id").addEventListener("click",()=>copyField("bucket-detail-id"));
$("copy-bucket-uri").addEventListener("click",()=>copyField("bucket-detail-uri"));
$("bucket-detail-dialog").addEventListener("close",()=>{currentBucket=null;});
$("bucket-create-key").addEventListener("click",()=>{
  const bucket=currentBucket;if(!bucket)return;
  $("bucket-detail-dialog").close();location.hash="keys";setView("keys");openCreate(bucket.id);
});
$("open-create-bucket").addEventListener("click",()=>{
  pendingBucket=null;$("bucket-create-form").reset();showError("bucket-create-error","");$("bucket-create-dialog").showModal();
});
$("bucket-create-dialog").addEventListener("cancel",event=>{if(bucketCreating)event.preventDefault();});
$("bucket-create-form").addEventListener("submit",async event=>{
  event.preventDefault();if(bucketCreating)return;showError("bucket-create-error","");
  const name=$("bucket-name").value;
  const quota=metadata.role==="tenant"?Math.round(Number($("bucket-quota").value)*1024**3):null;
  if(!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(name)){
    showError("bucket-create-error","桶名称须为 3～63 个小写字母、数字或短横线，且以字母或数字开头、结尾。");return;
  }
  if(!pendingBucket||pendingBucket.name!==name||pendingBucket.quota!==quota)pendingBucket={name,quota,id:crypto.randomUUID()};
  bucketCreating=true;const epoch=generation;$("bucket-create-submit").textContent="正在创建…";
  $("bucket-create-form").querySelectorAll("button,input").forEach(input=>input.disabled=true);
  try{
    const result=await api("/buckets",{method:"POST",payload:{name,request_id:pendingBucket.id,...(quota===null?{}:{quota_bytes:quota})}});
    if(epoch!==generation)return;
    buckets=buckets.filter(bucket=>bucket.id!==result.bucket.id);buckets.push(result.bucket);
    renderBuckets();$("bucket-create-dialog").close();pendingBucket=null;openBucketDetails(result.bucket);toast("存储桶已创建。");
    await refresh();
  }catch(error){if(epoch===generation)showError("bucket-create-error",error.message);}
  finally{bucketCreating=false;$("bucket-create-submit").textContent="创建存储桶";$("bucket-create-form").querySelectorAll("button,input").forEach(input=>input.disabled=false);}
});

let tenants=[],pendingTenant=null,tenantCreating=false,objectState=null,objectNext=null,objectCursors=[],objectCursor=null,objectEpoch=0,currentObject=null;
function configureRole(){
  const tenant=metadata.role==="tenant";
  $("nav-tenants").hidden=tenant||!metadata.role;$("nav-usage").hidden=!tenant;
  $("account-name").textContent=tenant?metadata.tenant.name:"平台主管理员";
  $("bucket-quota-field").hidden=!tenant;
  $("bucket-name").maxLength=tenant?48:63;
  $("bucket-name").pattern=tenant?"[a-z0-9][a-z0-9-]{1,46}[a-z0-9]":"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]";
  $("bucket-name-hint").textContent=tenant?"3～48 个小写字母、数字或短横线。实际 S3 桶名称会自动添加客户前缀。":"3～63 个小写字母、数字或短横线。名称须唯一。";
}
function route(){
  const [name,query=""]=location.hash.slice(1).split("?",2);
  let view=["keys","buckets","tenants","usage","objects"].includes(name)?name:"keys";
  if((view==="tenants"&&metadata.role!=="platform")||(view==="usage"&&metadata.role!=="tenant"))view="buckets";
  setView(view);
  if(view==="tenants")loadTenants();
  if(view==="usage")loadUsage();
  if(view==="objects"){
    const params=new URLSearchParams(query);
    objectState={bucket:params.get("bucket")||"",prefix:params.get("prefix")||"",mode:params.get("mode")==="flat"?"flat":"tree"};
    objectCursor=null;objectCursors=[];loadObjects();
  }
}
async function loadTenants(){
  showError("tenant-error","");
  try{
    const result=await api("/tenants");tenants=result.items;const rows=$("tenant-rows");rows.replaceChildren();
    for(const tenant of tenants){
      const row=element("tr"),name=element("td");name.append(element("strong",tenant.name),element("div",tenant.id,"key-id"));
      row.append(name,element("td",formatBytes(tenant.allocated_bytes)+" / "+formatBytes(tenant.quota_bytes)),element("td",[tenant.max_buckets,tenant.max_keys,tenant.max_concurrent].join(" / ")),element("td",tenant.status));
      const actions=element("td"),button=element("button",tenant.status==="active"?"暂停客户":"恢复客户","row-button");
      button.addEventListener("click",async()=>{
        const status=tenant.status==="active"?"suspended":"active";
        if(!confirm(status==="suspended"?"暂停后，该客户的控制台、S3 密钥和扩展 API 将不可用。继续？":"恢复该客户的访问？"))return;
        button.disabled=true;try{await api("/tenants/"+tenant.id+"/status",{method:"POST",payload:{status}});await loadTenants();}catch(error){showError("tenant-error",error.message);}finally{button.disabled=false;}
      });actions.append(button);row.append(actions);rows.append(row);
    }
    $("tenant-empty").hidden=tenants.length!==0;
  }catch(error){if(authenticated)showError("tenant-error",error.message);}
}
async function loadUsage(){
  showError("usage-error","");
  try{
    const value=await api("/usage"),t=value.tenant;
    $("usage-bytes").textContent=formatBytes(value.used_bytes)+" / "+formatBytes(t.quota_bytes);
    $("usage-allocation").textContent="已分配桶配额 "+formatBytes(value.allocated_bytes)+" · "+value.objects+" 个对象";
    $("usage-counts").textContent=value.bucket_count+" / "+value.key_count;
    $("usage-limits").textContent="上限：桶 "+t.max_buckets+" · 密钥 "+t.max_keys;
    $("usage-concurrency").textContent=String(t.max_concurrent);
  }catch(error){if(authenticated)showError("usage-error",error.message);}
}
$("refresh-tenants").addEventListener("click",loadTenants);
$("refresh-usage").addEventListener("click",loadUsage);
$("open-tenant").addEventListener("click",()=>{pendingTenant=null;$("tenant-form").reset();showError("tenant-create-error","");$("tenant-dialog").showModal();});
$("tenant-dialog").addEventListener("cancel",event=>{if(tenantCreating)event.preventDefault();});
$("tenant-form").addEventListener("submit",async event=>{
  event.preventDefault();if(tenantCreating)return;showError("tenant-create-error","");
  const payload={name:$("tenant-name").value.trim(),quota_bytes:Math.round(Number($("tenant-quota").value)*1024**3),max_buckets:Number($("tenant-buckets").value),max_keys:Number($("tenant-keys").value),max_concurrent:Number($("tenant-concurrency").value)};
  const fingerprint=JSON.stringify(payload);if(!pendingTenant||pendingTenant.fingerprint!==fingerprint)pendingTenant={fingerprint,id:crypto.randomUUID()};
  payload.request_id=pendingTenant.id;tenantCreating=true;$("tenant-submit").disabled=true;
  try{
    const result=await api("/tenants",{method:"POST",payload}),c=result.credentials;
    $("tenant-dialog").close();pendingTenant=null;
    openDetails({accessKeyId:c.access_key_id,name:result.tenant.name+" / 客户管理密钥",role:"owner",buckets:[],credentialBucket:""},c.secret_access_key);
    toast("客户已开通，请将此客户专属凭据安全交付。");await loadTenants();
  }catch(error){if(authenticated)showError("tenant-create-error",error.message);}
  finally{tenantCreating=false;$("tenant-submit").disabled=false;}
});
$("revoke-key").addEventListener("click",async()=>{
  const key=currentKey;if(!key||key.role!=="app"||!confirm("撤销后，此应用的 S3 与扩展 API 将无法使用该密钥。继续？"))return;
  $("revoke-key").disabled=true;
  try{await api("/keys/"+key.accessKeyId+"/revoke",{method:"POST",payload:{}});$("detail-dialog").close();toast("应用密钥已撤销。");await refresh();}catch(error){showError("detail-error",error.message);}finally{$("revoke-key").disabled=false;}
});
function navigateObjects(bucket,prefix="",mode="tree"){
  const hash="objects?"+new URLSearchParams({bucket,prefix,mode});
  if(location.hash.slice(1)===hash)route();else location.hash=hash;
}
$("bucket-browse").addEventListener("click",()=>{const bucket=currentBucket;if(bucket){$("bucket-detail-dialog").close();navigateObjects(bucket.id);}});
async function loadObjects(){
  const epoch=++objectEpoch,state={...objectState};showError("objects-error","");$("object-rows").replaceChildren();$("object-caption").textContent="正在加载…";
  $("object-prefix").value=state.prefix;$("object-mode").value=state.mode;
  try{
    const params={bucket_id:state.bucket,prefix:state.prefix,mode:state.mode};if(objectCursor)params.cursor=objectCursor;
    const data=await api("/objects?"+new URLSearchParams(params));if(epoch!==objectEpoch)return;
    $("objects-title").textContent=data.bucket.name;$("objects-subtitle").textContent="s3://"+data.bucket.name+"/"+state.prefix;
    const crumbs=$("object-breadcrumbs");crumbs.replaceChildren();const root=element("button","根目录","text-button");root.addEventListener("click",()=>navigateObjects(state.bucket,"",state.mode));crumbs.append(root);
    let prefix="";for(const part of state.prefix.split("/").filter(Boolean)){prefix+=part+"/";const target=prefix,button=element("button",part,"text-button");button.addEventListener("click",()=>navigateObjects(state.bucket,target,state.mode));crumbs.append(element("span","/","muted"),button);}
    const rows=$("object-rows");
    for(const directory of data.directories){
      const row=element("tr"),cell=element("td"),button=element("button","▱ "+directory.slice(state.prefix.length),"row-button");
      button.addEventListener("click",()=>navigateObjects(state.bucket,directory,state.mode));cell.append(button);row.append(cell,element("td","目录"),element("td","—"),element("td",""));rows.append(row);
    }
    for(const object of data.items){
      const row=element("tr"),name=element("td"),button=element("button",object.key.slice(state.prefix.length)||object.key,"row-button");button.title=object.key;
      button.addEventListener("click",()=>openObject(state.bucket,object.key));name.append(button);
      const actions=element("td"),download=element("button","下载","row-button");download.addEventListener("click",()=>downloadObject(state.bucket,object.key));
      actions.append(download);row.append(name,element("td",formatBytes(object.size)),element("td",date(object.lastModified),"muted"),actions);rows.append(row);
    }
    objectNext=data.nextCursor;$("objects-next").disabled=!objectNext;$("objects-previous").disabled=objectCursors.length===0;
    $("object-empty").hidden=rows.children.length!==0;$("object-caption").textContent=data.directories.length+" 个目录 · "+data.items.length+" 个对象";
  }catch(error){if(epoch===objectEpoch&&authenticated){showError("objects-error",error.message);$("object-caption").textContent="加载失败";}}
}
$("object-search-form").addEventListener("submit",event=>{event.preventDefault();navigateObjects(objectState.bucket,$("object-prefix").value,$("object-mode").value);});
$("objects-next").addEventListener("click",()=>{if(objectNext){objectCursors.push(objectCursor);objectCursor=objectNext;loadObjects();}});
$("objects-previous").addEventListener("click",()=>{if(objectCursors.length){objectCursor=objectCursors.pop();loadObjects();}});
async function downloadObject(bucket,key){
  try{
    const result=await api("/objects/link",{method:"POST",payload:{bucket_id:bucket,key}});
    const link=element("a");link.href=result.url;link.rel="noopener";link.download=key.split("/").pop()||"download";document.body.append(link);link.click();link.remove();
  }catch(error){if(authenticated){toast(error.message);if($("object-dialog").open)showError("object-detail-error",error.message);}}
}
function clearObject(){currentObject=null;$("object-image").removeAttribute("src");$("object-image").hidden=true;$("object-text").textContent="";$("object-text").hidden=true;$("object-facts").textContent="";$("object-preview-note").textContent="";}
async function openObject(bucket,key){
  clearObject();currentObject={bucket,key};const selected=currentObject;$("object-title").textContent=key;showError("object-detail-error","");$("object-preview").hidden=true;$("object-dialog").showModal();
  try{
    const result=await api("/objects/detail?"+new URLSearchParams({bucket_id:bucket,key}));if(currentObject!==selected)return;
    Object.assign(selected,result);$("object-facts").textContent=JSON.stringify({key,size:formatBytes(result.size),contentType:result.contentType,contentEncoding:result.contentEncoding,etag:result.etag,lastModified:result.lastModified,metadata:result.metadata},null,2);
    $("object-preview").hidden=!(result.imagePreview||result.textPreview);
  }catch(error){if(currentObject===selected)showError("object-detail-error",error.message);}
}
$("object-dialog").addEventListener("close",clearObject);
$("object-download").addEventListener("click",()=>{if(currentObject)downloadObject(currentObject.bucket.id||currentObject.bucket,currentObject.key);});
$("object-preview").addEventListener("click",async()=>{
  const selected=currentObject;if(!selected)return;$("object-preview").disabled=true;showError("object-detail-error","");
  try{
    const bucket=selected.bucket.id||selected.bucket;
    if(selected.imagePreview){
      const result=await api("/objects/link",{method:"POST",payload:{bucket_id:bucket,key:selected.key,inline:true}});
      if(currentObject===selected){$("object-image").src=result.url;$("object-image").hidden=false;$("object-preview-note").textContent="位图预览（最大 10 MiB）";}
    }else{
      const result=await api("/objects/preview?"+new URLSearchParams({bucket_id:bucket,key:selected.key}));
      if(currentObject===selected){$("object-text").textContent=result.text;$("object-text").hidden=false;$("object-preview-note").textContent=result.truncated?"仅显示前 64 KiB；下载可查看完整内容。":"UTF-8 文本预览";}
    }
  }catch(error){if(currentObject===selected)showError("object-detail-error",error.message);}finally{$("object-preview").disabled=false;}
});
document.addEventListener("visibilitychange",()=>{if(document.hidden&&$("object-dialog").open)$("object-dialog").close();});
