"""Tenant metadata only. Secret keys remain in Garage, never in this database."""
import asyncio,contextlib,json,pathlib,secrets,sqlite3,time,uuid

class TenantError(Exception):
    def __init__(self,status,code,message):self.status=status;self.code=code;self.message=message

SCHEMA="""
CREATE TABLE IF NOT EXISTS tenants(
 id TEXT PRIMARY KEY,name TEXT NOT NULL,prefix TEXT NOT NULL UNIQUE,status TEXT NOT NULL,
 created REAL NOT NULL,quota_bytes INTEGER NOT NULL,max_buckets INTEGER NOT NULL,max_keys INTEGER NOT NULL,
 max_concurrent INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_keys(
 id TEXT PRIMARY KEY,access_key_id TEXT UNIQUE,tenant_id TEXT NOT NULL REFERENCES tenants(id),
 role TEXT NOT NULL,status TEXT NOT NULL,created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS tenant_keys_owner ON tenant_keys(tenant_id,status);
CREATE TABLE IF NOT EXISTS tenant_buckets(
 id TEXT PRIMARY KEY,garage_id TEXT UNIQUE,name TEXT NOT NULL UNIQUE,label TEXT NOT NULL,
 tenant_id TEXT NOT NULL REFERENCES tenants(id),quota_bytes INTEGER NOT NULL,status TEXT NOT NULL,created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS tenant_buckets_owner ON tenant_buckets(tenant_id,status);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY,tenant_id TEXT,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,created REAL NOT NULL
);
"""
class Registry:
    def __init__(self,path,readonly=False):self.path=pathlib.Path(path);self.readonly=readonly
    @contextlib.contextmanager
    def connect(self):
        if self.readonly:
            conn=sqlite3.connect(self.path.resolve().as_uri()+"?mode=ro",uri=True,timeout=10)
        else:conn=sqlite3.connect(str(self.path),timeout=10)
        conn.row_factory=sqlite3.Row;conn.execute("PRAGMA foreign_keys=ON");conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback();raise
        finally:conn.close()
    def initialize(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as conn:conn.executescript(SCHEMA)
        self.path.chmod(0o640)
    def query(self,sql,params=()):
        with self.connect() as conn:return [dict(row) for row in conn.execute(sql,params)]
    def one(self,sql,params=()):
        rows=self.query(sql,params);return rows[0] if rows else None
    def tenant(self,ident):
        row=self.one("SELECT * FROM tenants WHERE id=?",(ident,))
        if row is None:raise TenantError(404,"tenant_not_found","没有找到该租户。")
        return row
    def tenants(self):return self.query("SELECT * FROM tenants ORDER BY created DESC")
    def key(self,ident):
        return self.one("""SELECT k.*,t.status tenant_status,t.name tenant_name,t.prefix,t.max_concurrent
            FROM tenant_keys k JOIN tenants t ON t.id=k.tenant_id
            WHERE k.access_key_id=? AND k.status='active'""",(ident,))
    def keys(self,tenant):return self.query("SELECT * FROM tenant_keys WHERE tenant_id=? AND status='active' ORDER BY created DESC",(tenant,))
    def buckets(self,tenant):
        return self.query("SELECT * FROM tenant_buckets WHERE tenant_id=? AND status='ready' ORDER BY created DESC",(tenant,))
    def bucket(self,ident,tenant=None):
        sql="SELECT * FROM tenant_buckets WHERE garage_id=? AND status='ready'";params=[ident]
        if tenant is not None:sql+=" AND tenant_id=?";params.append(tenant)
        return self.one(sql,params)
    def create_tenant(self,name,quota_bytes,max_buckets,max_keys,max_concurrent):
        ident=uuid.uuid4().hex
        with self.connect() as conn:
            conn.execute("INSERT INTO tenants VALUES(?,?,?,?,?,?,?,?,?)",
                (ident,name,"t-"+secrets.token_hex(6)+"-","provisioning",time.time(),quota_bytes,max_buckets,max_keys,max_concurrent))
        return self.tenant(ident)
    def activate_tenant(self,ident):
        with self.connect() as conn:conn.execute("UPDATE tenants SET status='active' WHERE id=?",(ident,))
    def set_status(self,ident,status):
        with self.connect() as conn:conn.execute("UPDATE tenants SET status=? WHERE id=?",(status,ident))
    def discard_tenant(self,ident):
        with self.connect() as conn:
            conn.execute("DELETE FROM tenant_keys WHERE tenant_id=?",(ident,));conn.execute("DELETE FROM tenants WHERE id=? AND status='provisioning'",(ident,))
    def reserve_key(self,tenant,role="app"):
        ident=uuid.uuid4().hex
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row=conn.execute("SELECT * FROM tenants WHERE id=?",(tenant,)).fetchone()
            if row is None:raise TenantError(404,"tenant_not_found","没有找到该租户。")
            count=conn.execute("SELECT COUNT(*) FROM tenant_keys WHERE tenant_id=? AND status IN ('active','pending')",(tenant,)).fetchone()[0]
            if count>=row["max_keys"]:raise TenantError(409,"key_limit","已达到该租户的密钥数量上限。")
            conn.execute("INSERT INTO tenant_keys VALUES(?,?,?,?,?,?)",(ident,None,tenant,role,"pending",time.time()))
        return ident
    def finish_key(self,reservation,access_key_id):
        with self.connect() as conn:conn.execute("UPDATE tenant_keys SET access_key_id=?,status='active' WHERE id=?",(access_key_id,reservation))
    def release_key(self,reservation):
        with self.connect() as conn:conn.execute("DELETE FROM tenant_keys WHERE id=? AND status='pending'",(reservation,))
    def revoke_key(self,access_key_id):
        with self.connect() as conn:conn.execute("UPDATE tenant_keys SET status='revoked' WHERE access_key_id=?",(access_key_id,))
    def reserve_bucket(self,tenant,label,quota_bytes):
        ident=uuid.uuid4().hex
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row=conn.execute("SELECT * FROM tenants WHERE id=?",(tenant,)).fetchone()
            if row is None or row["status"]!="active":raise TenantError(403,"tenant_inactive","租户当前不可用。")
            count,allocated=conn.execute("SELECT COUNT(*),COALESCE(SUM(quota_bytes),0) FROM tenant_buckets WHERE tenant_id=?",(tenant,)).fetchone()
            if count>=row["max_buckets"]:raise TenantError(409,"bucket_limit","已达到该租户的存储桶数量上限。")
            if allocated+quota_bytes>row["quota_bytes"]:raise TenantError(409,"quota_allocation_exceeded","新桶配额超过租户剩余可分配容量。")
            name=row["prefix"]+label
            if conn.execute("SELECT 1 FROM tenant_buckets WHERE name=?",(name,)).fetchone():
                raise TenantError(409,"bucket_exists","同名存储桶已存在或正在创建。")
            conn.execute("INSERT INTO tenant_buckets VALUES(?,?,?,?,?,?,?,?)",
                (ident,None,name,label,tenant,quota_bytes,"pending",time.time()))
        return self.one("SELECT * FROM tenant_buckets WHERE id=?",(ident,))
    def finish_bucket(self,reservation,garage_id):
        with self.connect() as conn:conn.execute("UPDATE tenant_buckets SET garage_id=?,status='ready' WHERE id=?",(garage_id,reservation))
    def fail_bucket(self,reservation,garage_id=None,cleaned=False):
        with self.connect() as conn:
            if cleaned:conn.execute("DELETE FROM tenant_buckets WHERE id=?",(reservation,))
            else:conn.execute("UPDATE tenant_buckets SET status='provisioning_error',garage_id=? WHERE id=?",(garage_id,reservation))
    def allocated(self,tenant):
        return self.one("SELECT COALESCE(SUM(quota_bytes),0) total FROM tenant_buckets WHERE tenant_id=?",(tenant,))["total"]
    def audit(self,tenant,actor,action,target):
        with self.connect() as conn:conn.execute("INSERT INTO audit(tenant_id,actor,action,target,created) VALUES(?,?,?,?,?)",
            (tenant,actor,action,target,time.time()))
    def audits(self,tenant=None):
        if tenant:return self.query("SELECT action,target,created FROM audit WHERE tenant_id=? ORDER BY id DESC LIMIT 100",(tenant,))
        return self.query("SELECT tenant_id,actor,action,target,created FROM audit ORDER BY id DESC LIMIT 100")
    async def call(self,method,*args,**kwargs):return await asyncio.to_thread(getattr(self,method),*args,**kwargs)

def request_key(headers):
    authorization=headers.get("Authorization","")
    if not authorization.startswith("AWS4-HMAC-SHA256 "):return None
    try:
        fields=dict(item.strip().split("=",1) for item in authorization[len("AWS4-HMAC-SHA256 "):].split(","))
        return fields["Credential"].split("/",1)[0]
    except (ValueError,KeyError):return None
