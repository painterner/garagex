import copy,uuid
from tests.admin.test_admin import FakeGarage,MASTER,BUCKET
from garagex.admin.app import AdminError
class TenantGarage(FakeGarage):
    def __init__(self):
        super().__init__()
        self.keys[MASTER['access_key_id']]={'accessKeyId':MASTER['access_key_id'],'name':'platform','secretAccessKey':MASTER['secret_access_key'],'expired':False,'buckets':[],'permissions':{'createBucket':False}}
    async def call(self,action,payload=None,query=None):
        query=query or {}
        if action=='CreateBucket' and 'localAlias' not in payload:
            self.calls.append(action);ident=uuid.uuid4().hex+uuid.uuid4().hex
            row={'id':ident,'globalAliases':[payload['globalAlias']],'objects':0,'bytes':0,'keys':[],'quotas':{},'created':None}
            self.bucket_rows[ident]=row;return copy.deepcopy(row)
        if action=='AllowBucketKey':
            self.calls.append(action)
            if self.fail_allow:raise AdminError(502,'garage_error','failed')
            key=self.keys[payload['accessKeyId']];bucket=self.bucket_rows[payload['bucketId']]
            key['buckets'].append({'id':bucket['id'],'globalAliases':bucket['globalAliases'],'permissions':payload['permissions']})
            bucket['keys'].append({'accessKeyId':key['accessKeyId'],'name':key['name'],'permissions':payload['permissions']})
            return {}
        if action=='UpdateBucket':
            self.calls.append(action);self.bucket_rows[query['id']]['quotas']=payload['quotas'];return copy.deepcopy(self.bucket_rows[query['id']])
        if action=='DeleteBucket':
            self.calls.append(action);self.bucket_rows.pop(query['id'],None);return {}
        if action=='UpdateKey':
            self.calls.append(action);self.keys[query['id']]['expired']='expiration' in payload;return {}
        return await super().call(action,payload,query)
