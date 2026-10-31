# GarageX

在 Garage S3 上增加管理控制台、流式代理下载、纯网络测速与过程报告。
面向小规格服务器部署；保留标准 S3 接口，所有扩展 API 使用同一套 S3 SigV4 凭据。

## 当前能力

- 私有 S3 存储桶、对象上传下载、分片上传和预签名下载链接。
- Web 管理控制台：创建和查看桶、目录/前缀/分页浏览文件、详情、下载、文本和位图预览。
- 对外客户自助：平台开通客户，客户用自己的 S3 管理密钥登录，管理自己的桶、应用密钥和用量。
- 租户资源归属校验、桶/密钥数量与代理并发限制、桶容量配额、客户暂停/恢复、应用密钥撤销。
- 从公网 URL 边下载、边写入 S3、边向调用方返回文件。
- 下游断开时继续下载，或停止上游并保存已收到的文件前缀。
- 每次下载可配置对象保留秒数，默认永久；持久化到期清理计划。
- 下游/上游纯网络测试，不写入 S3；JSON 和离线 HTML 延迟/吞吐率报告。
- 公网上游及每次重定向的地址校验，禁止内网、元数据与本机地址。

客户使用各自的 S3 管理密钥；不要把平台主管理密钥交给客户。
应用密钥用于数据 API，不能登录控制台。没有独立的客户密码或代理 Token。

## 新机器快速部署

要求：Linux、Python 3.12+、Docker Engine 与 Compose v2，域名直接指向机器。
80/TCP、443/TCP、443/UDP 用于 Caddy HTTPS，Garage 管理端口不对公网发布。

```bash
git clone https://github.com/painterner/garagex.git
cd garagex

# Ubuntu 可选安装步骤；已装 Docker 时跳过
sudo ./scripts/install-docker.sh

sudo ./scripts/deploy.sh \
  --domain s3.your-domain.example \
  --email admin@your-domain.example \
  --bucket garagex
```

打开：
- 管理控制台：`https://你的域名/admin/`
- 存储桶管理：`https://你的域名/admin/#buckets`
- 外部接入文档：`https://你的域名/docs/`

部署会在本机生成新的 S3 Access Key / Secret Key、Garage RPC 密钥与内部服务 Token；
每台新机器独立生成，不会复制作者服务器的密钥。

管理员在本机读取自己的凭据：

```bash
sudo cat .runtime/secrets/credentials.json
```

此文件含真实 Secret Key。管理控制台和扩展 API 使用同一对 S3 凭据；
内部 Garage 服务令牌不会交给浏览器或外部客户端。

## 开通客户与使用

1. 平台管理员登录 /admin/，在“客户租户”中开通客户，设置容量、桶数、密钥数和代理并发上限。
2. 将开通结果中的客户专属 S3 Access Key / Secret Key 安全交付。客户用这对密钥登录同一控制台。
3. 客户创建桶时填写标签和容量配额。实际 S3 桶名带自动分配的客户前缀，以控制台显示的完整名称为准。
4. 在桶详情中浏览文件，或创建只允许指定桶读写的应用密钥。客户应用密钥同时用于 S3、代理和网络测试。
5. 客户在“用量与配额”查看对象容量和数量；平台可暂停/恢复客户，客户可撤销自己的应用密钥。

同一客户的桶配额总和不能超过客户总配额。Garage 原生桶配额同样约束直接 S3 写入，
不是只在页面检查。统计来自 Garage，可能略有延迟；请求数和流量尚不提供计费结算。

代理 JSON 的 bucket 字段填写实际 S3 桶名或桶 ID。客户仅有一个可读写的桶时可以省略；
多个桶时必须指定。客户管理密钥可查看本客户任务；应用密钥只可查看自己创建的任务。
历史平台任务仅平台可查看。暂停会使客户原生 S3 密钥过期，恢复后重新启用。

桶内文件按 S3 Key 的前缀组织，目录为虚拟目录。文本只预览前 64 KiB；常见位图最多
10 MiB。HTML/SVG 以文本显示。文件下载使用 60 秒有效的临时链接；此链接持有者在
有效期内可下载该文件。控制台目前提供查看、预览和下载；上传可使用标准 S3 客户端。

## 数据和更新

持久化内容全部在被 Git 忽略的 `.runtime/`：
- `data/`、`meta/`：Garage 对象块和元数据。
- `jobs/`：代理任务、采样和清理计划。
- `tenants/`：客户归属、配额和审计元数据（不存 Secret Key）。
- `secrets/`、`garage.env`、`garage/`：本机私有凭据和服务配置。
- `caddy-data/`：TLS 证书与状态。

更新应用：

```bash
git pull --ff-only
sudo docker compose up -d --build
sudo docker compose logs --tail=50
```

配置生成器重复执行会保留已有密钥；同一运行目录的域名/初始桶变更会被拒绝，
需要单独迁移。不要删除 `.runtime/`，不要运行会删除忽略文件的 Git 清理命令。

备份需要同时保留对象数据、元数据、任务记录和密钥。单机初始配置没有跨机器
冗余；快照/备份或多节点部署需要按自己的数据可靠性要求配置。

## 外部 Python 客户端

```bash
python3 -m pip install boto3
export AWS_ACCESS_KEY_ID='YOUR_ACCESS_KEY'
export AWS_SECRET_ACCESS_KEY='YOUR_SECRET_KEY'
export AWS_DEFAULT_REGION='garage'
export S3_ENDPOINT='https://s3.your-domain.example'
export S3_BUCKET='garagex'

python3 docs/examples/garagex_client.py ls
python3 docs/examples/garagex_client.py upload file.bin uploads/file.bin
python3 docs/examples/garagex_client.py download uploads/file.bin -o saved.bin

python3 docs/examples/garagex_client.py proxy 'https://public-source.example/file.bin' \
  -o file.bin --disconnect-mode stop_keep --retention-seconds 60 \
  --report transfer.json --report-html transfer.html

python3 docs/examples/garagex_client.py network-test \
  --upstream 'https://public-source.example/file.bin' \
  --report network.json --report-html network.html
```

保留期限为对象保存完成后的秒数；省略/null 表示永久。部分文件使用原目标 Key，
状态为 `stopped`、`is_partial=true`，SHA-256 对应实际保留的前缀。它不代表完整原文件。
原有对象不会被代理覆盖。

下游实际接收速率与 HTTP RTT 由客户端采集；服务端向 Caddy 写出的速率与外部
客户端实际接收速率不同。上游延迟使用 Linux TCP SRTT。不可用测量保持为空。

## 开发与验证

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -t . -v
python scripts/scan_secrets.py
# 前端 DOM 交互测试（需要 Node 18+）
npm ci --ignore-scripts
npm test
```

普通测试不会访问真实 S3。可选真实集成测试：

```bash
TEST_REAL_S3=1 \
GARAGEX_CREDENTIALS=/path/to/your/private/credentials.json \
GARAGEX_S3_ENDPOINT=http://127.0.0.1:3900 \
python -m unittest discover -s tests -t . -v
```

真实测试使用随机对象 Key，结束时删除自己创建的对象。
`deploy/compose.test.yaml` 为隔离集成验证增加仅绑定回环的测试端口，不应作为公网配置。

## 隔离集成验证

开发时可使用 scripts/check-isolated.sh 在临时运行目录和回环端口部署测试实例，
包含真实 S3 分片、两个客户隔离、配额、代理、清理与暂停/恢复测试。
该脚本不会启动公网 Caddy；测试结束会移除自己的容器和临时数据。
需要 Docker、Python 3 和可拉取镜像的网络。运行命令：

```bash
sudo ./scripts/check-isolated.sh
```

## 发布前检查

```bash
python scripts/scan_secrets.py --history
# 可选：只在自己的机器核对已知私有值，输出不会显示值本身
python scripts/scan_secrets.py --secret-file /path/to/private/credentials.json
git status --short
```

只提交源代码、测试、文档和模板。运行目录、凭据、数据库、日志、虚拟环境均不提交。
请勿将本机 `docker compose config` 等可能展开密钥的输出粘贴到公开 Issue。

## 项目组成

- `garagex/proxy/`：流式代理、断开策略、到期清理、测速与报告。
- `garagex/admin/`：管理 API 与静态 Web 控制台。
- `garagex/auth.py`：S3 SigV4 签名校验。
- `garagex/bootstrap.py`：内部最小范围服务令牌初始化。
- `scripts/`：配置生成、部署、发布脱敏检查。
- `docs/`：可随部署域名生成的外部使用文档与独立客户端。
- `tests/`：认证、流式传输、TTL、管理与配置测试。

Garage、Caddy、Python 依赖均保留各自上游许可证；GarageX 自身许可证由仓库维护者另行确定。
