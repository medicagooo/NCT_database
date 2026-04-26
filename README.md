# NCT API SQL

基于 `Cloudflare Workers + D1 + R2 + Hono + Vite + React` 的全栈应用，用于：

- 接收下游推送数据并写入未加密原始表
- 根据原始表生成部分列加密的发布表，并维护版本号
- 记录 `nct-api-sql-sub` 定时上报的域名、版本号和上报次数
- 供各个 `nct-api-sql-sub` 主动拉取第二张表的发布数据
- 按子库版本从新到旧主动回拉 `nct_databack` 文件，并回灌到主库的 `secure_records` 与 `raw_records`
- 定时把 D1 三张表打包到 R2，并以邮件附件形式发出
- 提供 liquid glass 风格的管理台，用于查询、管理、分析、调试

生产环境默认通过 Cloudflare Workers 绑定的自定义域名对外提供服务，例如：

- 根路径公开 JSON：`https://api.example.com/`
- 管理台首页：`https://api.example.com/Console`
- API 基地址：`https://api.example.com/api/*`

## 架构

### D1 三表

1. `raw_records`
原始未加密数据，保存完整 JSON。
`ingest` 时会按顶层字段自动为本表补充 `payload_*` 动态列，方便直接查询。

2. `secure_records`
按 `encryptFields` 或 `DEFAULT_ENCRYPT_FIELDS` 拆分字段。
非敏感字段落在 `public_json`，敏感字段用 `ENCRYPTION_KEY` 做 `AES-GCM` 加密，版本号在本表递增维护。
同时会自动补充：

- 非敏感字段的 `public_*` 动态列
- 敏感字段的 `encrypted_*` 动态列

3. `downstream_clients`
作为第三张表，统一记录：

- `nct-api-sql-sub` 上报的 `serviceUrl`、`databackVersion`、`reportCount` 和原始 payload
- 主库最近一次成功推送到该子库的版本号与时间
- 主库最近一次成功回拉该子库的版本号、时间和状态

### 关键接口

- `GET /`
直接返回公开 JSON 数据：

```json
{
  "avg_age": 17,
  "last_synced": 123,
  "statistics": [
    { "province": "河南", "count": 12 },
    { "province": "湖北", "count": 66 }
  ],
  "data": [
    {
      "name": "学校名称",
      "addr": "学校地址",
      "province": "省份",
      "prov": "区、县",
      "else": "其他补充内容",
      "lat": 36.62728,
      "lng": 118.58882,
      "experience": "经历描述",
      "HMaster": "负责人/校长姓名",
      "scandal": "已知丑闻",
      "contact": "学校联系方式",
      "inputType": "受害者本人"
    }
  ]
}
```

其中：

- `data` 来自 D1 的 `raw_records`
- `statistics` 是对 `province` 的聚合统计
- `avg_age` 是对 `age` 的平均值，按四舍五入返回整数
- `last_synced` 是当前版本号，也就是 `secure_records.version` 的最大值

- `POST /api/ingest`
下游把数据推送到这里。Worker 会先按 ingest 顶层字段自动扩列并写 `raw_records`，再按加密规则更新 `secure_records`。

- `POST /api/sync`
已废弃。
主库不再负责主动推送到子库；`nct-api-sql-sub` 会自行拉取 `GET /api/public/secure-records`。

- `POST /api/sub/report`
只接收 `nct-api-sql-sub` 的上报。
收到后会把 `service`、`serviceUrl`、`databackVersion`、`reportCount`、`reportedAt` 存入第三张表。
同一子库的重复上报会按 `SUB_REPORT_MIN_INTERVAL_MS` 做限频，过快会返回 `429`。

- `POST /api/admin/push-now`
已废弃。
保留该路由仅为了给旧调用方返回明确的 `410` 提示，不再触发任何同步动作。

- `POST /api/admin/pull-now`
手动触发一次“主库 <- 已登记子库”的灾备回拉。
主库会按第三表中记录的子库版本，从新到旧调用子库的 `GET /api/export/nct_databack`，接收 JSON 附件文件并导入回主库。

- `GET /api/public/secure-records`
按版本对外公布表 2 数据，可选 `mode=full|delta` 和 `currentVersion`。

- `POST /api/admin/export-now`
手动触发导出。

### 定时任务

`wrangler.toml` 默认只配置导出 Cron：

```toml
[triggers]
crons = ["0 18 * * *"]
```

其中：

- `0 18 * * *` 表示每天 `18:00 UTC` 触发导出。按 `Asia/Shanghai` 来看，相当于次日 `02:00`

子库侧的同步不再由母库 cron 发起，而是由各自部署的 `nct-api-sql-sub` 在自己的定时任务中主动执行。

## 本地开发

### 1. 安装依赖

```bash
npm install
```

### 2. 创建 Cloudflare 资源

```bash
npx wrangler d1 create nct-api-sql
npx wrangler r2 bucket create nct-api-sql-exports
npx wrangler r2 bucket create nct-api-sql-exports-preview
```

把创建出来的 `database_id` 和 bucket 名称填回 [`wrangler.toml`](./wrangler.toml)。

### 3. 准备本地密钥和令牌

```bash
cp .env.example .dev.vars
openssl rand -base64 32
```

[`./.env.example`](./.env.example) 已按修改必要性排序列出当前项目的全部环境变量。
本地 Wrangler 仍然读取 `.dev.vars`，线上部署则把同名键写入 Cloudflare Variables / Secrets。

#### 必填环境变量

完整列表见 [`./.env.example`](./.env.example)。这里先标出真正需要优先确认的几项：

- 绝对必填：`ENCRYPTION_KEY`
- 平台绑定必填但不写进 `.env`：`DB`、`ASSETS`、`EXPORT_BUCKET`，在 [`wrangler.toml`](./wrangler.toml) 中绑定 D1、静态资产和 R2
- 管理台密码不再通过环境变量配置；部署后首次打开 `/Console` 设置
- 按功能必填：`RESEND_API_KEY`、`EXPORT_EMAIL_TO`、`EXPORT_EMAIL_FROM` 仅在你要启用邮件导出时需要

把生成的 base64 值写入 `ENCRYPTION_KEY`。服务间调用统一使用子库 `serviceUrl` 派生的 30 秒 HMAC Bearer token：

- 子库首次成功 `POST /api/sub/report` 即完成登记，母库保存 `sha256(serviceUrl)` 用于后续校验
- 子库上报、表单回传、母库推送 secure records、母库灾备回拉都按相同 30 秒窗口派生 token
- `GET /api/public/secure-records` 返回公开 payload，不再包 signed envelope；记录里的 `encryptedData` 仍然是母库 t2 字段密文
- 母库不再要求子库回传数据时做额外字段加密；子库本地普通 JSON 回传后，由母库按自身 `ENCRYPTION_KEY` 重新生成 t2

下面这些变量不是鉴权凭据，而是 mother/sub 同步调优项：

- `SUB_REPORT_MIN_INTERVAL_MS`
- `SUB_PULL_BATCH_SIZE`
- `SUB_PULL_MAX_ATTEMPTS`
- `SUB_PULL_RECORD_LIMIT`
- `SUB_PULL_RETRY_DELAY_MS`
- `SUB_PULL_TIMEOUT_MS`

管理台首次打开时会把你设置的管理员密码哈希写入 D1，之后登录会得到短期 session token。
`/api/ingest` 只接受已登录管理台 session，不再接受外部 `INGEST_TOKEN` Bearer 写入；母子库之间的数据同步走 `/api/sub/*`、`/api/push/secure-records` 和 `/api/export/nct_databack`。
新链路中不再有单独 bootstrap。双方直接以子库 `serviceUrl` 作为 verification seed，按 `NCT-MOTHER-AUTH-HMAC-SHA256-T30-V1` 每 30 秒派生短期 Bearer token，并用相邻时间窗口复算验证。无法验证的 report / form-records 请求会收到伪成功响应，但母库不落库、不触发推送。母库推送 `POST /api/push/secure-records` 和灾备回拉 `GET /api/export/nct_databack` 也带同样的 Bearer token；`nct_databack` 导出文件明文传输，不再使用 proof 字段。
`SUB_REPORT_MIN_INTERVAL_MS` 用于限制主库接收子库上报的最小时间间隔。
`SUB_PULL_BATCH_SIZE` 表示每轮最多处理多少个已登记子库。
`SUB_PULL_RECORD_LIMIT` 表示每次从单个子库拉取多少条 `nct_databack` 记录。
`SUB_PULL_MAX_ATTEMPTS` 表示单次子库导出请求最多连续尝试多少次，默认 5。
`SUB_PULL_RETRY_DELAY_MS` 表示失败后再次请求同一子库导出文件前等待多久，默认 60000 毫秒。
`SUB_PULL_TIMEOUT_MS` 表示主库请求子库导出文件时的超时时间。

生成推荐密钥的最小命令：

```bash
openssl rand -base64 32
```

### 4. 执行 D1 migration

```bash
npm run db:migrate
```

如果你直接运行 `npm run dev`，这一步现在会自动执行。
项目会先在本地创建或更新一个调试用 D1 数据库，然后再启动 Vite 和 Wrangler。
本地持久化目录固定为 `.wrangler/state`。

### 5. 启动开发环境

```bash
npm run dev
```

默认会同时启动：

- Vite 前端 Console：`http://127.0.0.1:5174/Console`
- Wrangler 本地 Worker：`http://127.0.0.1:8787`

本地开发时可以这样理解：

- `http://127.0.0.1:5174/Console` 用来看管理台
- `http://127.0.0.1:8787/` 用来看 Worker 返回的公开 JSON
- `http://127.0.0.1:8787/api/*` 用来直接调试 API

其中 `npm run dev` 会先自动执行：

```bash
node scripts/prepare-local-d1.mjs
```

它会调用：

```bash
npx wrangler d1 migrations apply DB --local --persist-to .wrangler/state
```

也就是说，只要你执行一次 `npm run dev`，本地调试 D1 库就会被自动建立好。

注意：Cloudflare Workers 在生产环境不是传统“监听自定义端口”的模式；`POST /api/ingest` 只作为管理台登录态下的手动写入入口，不再承接外部 token 写入。

### 动态扩列规则

`ingest` 接收到新的顶层字段时，会自动对 D1 执行 `ALTER TABLE ... ADD COLUMN`。
为了避免和系统列冲突，动态列名会做安全规整，并带上短哈希后缀，例如：

- `payload_city_x1y2z3`
- `public_score_a8k2m1`
- `encrypted_phone_q9w8e7`

规则说明：

- 只针对 payload 的顶层字段自动扩列
- 标量会直接转成字符串写入动态列
- 对象或数组会序列化成 JSON 字符串写入动态列
- 原始 JSON 列仍然保留，作为完整数据兜底

## Cloudflare Workers 部署

本文档后续涉及的生产环境示例统一以 `https://api.example.com` 作为占位域名。

### 1. 登录并创建资源

```bash
npx wrangler login
npx wrangler whoami
npm install
npx wrangler d1 create nct-api-sql
npx wrangler r2 bucket create nct-api-sql-exports
npx wrangler r2 bucket create nct-api-sql-exports-preview
```

把 `wrangler d1 create` 返回的 `database_id` 写回 [`wrangler.toml`](./wrangler.toml)：

```toml
[[d1_databases]]
binding = "DB"
database_name = "nct-api-sql"
database_id = "替换为线上 D1 database_id"
migrations_dir = "./migrations"
```

确认 R2 绑定：

```toml
[[r2_buckets]]
binding = "EXPORT_BUCKET"
bucket_name = "nct-api-sql-exports"
preview_bucket_name = "nct-api-sql-exports-preview"
```

### 2. 绑定自定义域名

建议使用 Workers Custom Domains 绑定 `api.example.com`。用 `wrangler.toml` 管理时加入：

```toml
[[routes]]
pattern = "api.example.com"
custom_domain = true
```

也可以在 Cloudflare Dashboard 的 Worker 设置页中添加 Custom Domain。正式环境如果不想暴露 `*.workers.dev`，把 `workers_dev = false`。

### 3. 设置生产 Secrets

生成母库字段加密密钥：

```bash
openssl rand -base64 32
```

写入 Cloudflare Secrets：

```bash
npx wrangler secret put ENCRYPTION_KEY
```

按功能可选：

```bash
npx wrangler secret put RESEND_API_KEY
```

说明：

- `ENCRYPTION_KEY` 使用上面生成的 base64 值。
- `EXPORT_EMAIL_TO` 和 `EXPORT_EMAIL_FROM` 可以放在 `[vars]`，也可以作为 Secrets。

### 4. 远端迁移并部署

```bash
npm run db:migrate:remote
npm run deploy
```

`npm run deploy` 会先执行 `vite build`，再通过 `wrangler deploy` 发布 Worker 与管理台静态资产。

部署后首次打开 `https://api.example.com/Console` 设置管理员密码。

### 5. Cloudflare Dashboard 网页端部署

如果希望主要在 Cloudflare 网页上完成部署，可以使用 Workers Builds 连接 Git 仓库。网页部署仍会读取本目录的 [`wrangler.toml`](./wrangler.toml)，因此先确认 `name = "nct-api-sql"`、`main = "src/worker/index.ts"`、`[assets]`、Cron、D1 和 R2 绑定都已提交到仓库；不要把示例里的 `database_id = "00000000-0000-0000-0000-000000000000"` 留在线上配置中。

推荐步骤：

1. 在 Cloudflare Dashboard 进入 `Workers & Pages`，创建或选择名为 `nct-api-sql` 的 Worker。
2. 打开该 Worker 的 `Settings` -> `Builds`，选择 `Connect`，连接 GitHub / GitLab 仓库。
3. 构建设置按项目位置填写：
   - Repository root 如果是整个 `nct` 仓库，Root directory 填 `NCT_database`；如果本项目是独立仓库，留空或填 `/`。
   - Production branch 填实际生产分支，例如 `main`。
   - Build command 填 `npm run check && npm run build`。
   - Deploy command 填 `npx wrangler deploy`。
4. 在 `D1 SQL database` 页面创建数据库 `nct-api-sql`，复制数据库 ID，写回并提交 [`wrangler.toml`](./wrangler.toml) 的 `[[d1_databases]]`；也可以在 Worker 的 `Settings` -> `Bindings` 手动添加 `D1 database` 绑定，变量名必须是 `DB`。
5. 在 `R2` 页面创建 `nct-api-sql-exports` 和 `nct-api-sql-exports-preview` 两个 bucket，并在 Worker 的 `Settings` -> `Bindings` 确认 `R2 bucket` 绑定变量名为 `EXPORT_BUCKET`。
6. 在 D1 数据库的 `Console` 中按文件名顺序执行 [`migrations`](./migrations) 里的 SQL。更稳妥的方式仍是在本地执行 `npm run db:migrate:remote`，避免漏跑某个 migration。
7. 在 Worker 的 `Settings` -> `Variables and Secrets` 中添加生产配置：
   - Variables：`APP_NAME`、`DEFAULT_ENCRYPT_FIELDS`、`EXPORT_EMAIL_TO`、`EXPORT_EMAIL_FROM`、`SUB_AUTH_MAX_FAILURES`、`SUB_REPORT_MIN_INTERVAL_MS`、`SUB_PULL_BATCH_SIZE`、`SUB_PULL_MAX_ATTEMPTS`、`SUB_PULL_RECORD_LIMIT`、`SUB_PULL_RETRY_DELAY_MS`、`SUB_PULL_TIMEOUT_MS`
   - Secrets：`ENCRYPTION_KEY`、`RESEND_API_KEY`
8. 在 `Settings` -> `Triggers` 确认 Cron 触发器包含 `0 18 * * *`。
9. 在 `Settings` -> `Domains & Routes` -> `Add` -> `Custom Domain` 绑定 `api.example.com`。
10. 推送一个提交触发 Workers Builds。部署成功后打开 `https://api.example.com/Console` 设置管理员密码，再检查 `https://api.example.com/api/health` 和 `https://api.example.com/`。

Cloudflare 官方参考：[`Workers Builds`](https://developers.cloudflare.com/workers/ci-cd/builds/)、[`Workers Static Assets`](https://developers.cloudflare.com/workers/static-assets/)、[`D1 Dashboard`](https://developers.cloudflare.com/d1/get-started/)、[`R2 Buckets`](https://developers.cloudflare.com/r2/buckets/create-buckets/)、[`Variables and Secrets`](https://developers.cloudflare.com/workers/configuration/secrets/)、[`Custom Domains`](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)。

### 生产访问约定

假设你的自定义域名是 `https://api.example.com`，则：

- 公开 JSON：`https://api.example.com/`
- 管理台入口：`https://api.example.com/Console`
- 健康检查：`https://api.example.com/api/health`
- 数据写入：`https://api.example.com/api/ingest`
- 灾备回拉：`https://api.example.com/api/admin/pull-now`
- 子库上报：`https://api.example.com/api/sub/report`
- 公布数据：`https://api.example.com/api/public/secure-records`
- 管理导出：`https://api.example.com/api/admin/export-now`

## 邮件导出

当前实现默认用 `Resend` 发附件邮件，需要在 `.dev.vars` 或 Cloudflare secret 中设置：

- `RESEND_API_KEY`
- `EXPORT_EMAIL_TO`
- `EXPORT_EMAIL_FROM`

导出流程会：

1. 全量查询 D1 三张表
2. 生成 JSON + CSV 文件
3. 打成 zip
4. 上传到 R2
5. 把 zip 作为附件发往目标邮箱

## 示例请求

### 写入原始数据

`/api/ingest` 现在只给管理台登录态使用，外部 Bearer token 写入已关闭。本地开发示例：

```bash
curl -X POST http://127.0.0.1:8787/api/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_CONSOLE_SESSION_TOKEN" \
  -d '{
    "records": [
      {
        "recordKey": "patient-1001",
        "source": "hospital-a",
        "encryptFields": ["name", "phone", "email"],
        "payload": {
          "id": "patient-1001",
          "name": "Zhang San",
          "phone": "13800000000",
          "email": "demo@example.com",
          "city": "Shanghai",
          "score": 91
        }
      }
    ]
  }'
```

生产环境自定义域名示例：

```bash
curl -X POST https://api.example.com/api/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_CONSOLE_SESSION_TOKEN" \
  -d '{
    "records": [
      {
        "recordKey": "patient-1001",
        "source": "hospital-a",
        "encryptFields": ["name", "phone", "email"],
        "payload": {
          "id": "patient-1001",
          "name": "Zhang San",
          "phone": "13800000000",
          "email": "demo@example.com",
          "city": "Shanghai",
          "score": 91
        }
      }
    ]
  }'
```

### 手动触发灾备回拉

```bash
curl -X POST https://api.example.com/api/admin/pull-now \
  -H "Authorization: Bearer YOUR_CONSOLE_SESSION_TOKEN"
```

### 子库上报

`/api/sub/report` 只接受 `nct-api-sql-sub` 的上报，其他 `service` 会被拒绝。
母库识别 `serviceWatermark` 后，会用 `serviceUrl` 派生的 30 秒 HMAC Bearer token 验证请求；首次验证成功会登记该子库。

```bash
curl -X POST https://api.example.com/api/sub/report \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer SERVICE_URL_DERIVED_30S_HMAC" \
  -d '{
    "service": "NCT API SQL Sub",
    "serviceWatermark": "nct-api-sql-sub:v1",
    "serviceUrl": "https://sub.example.com",
    "databackVersion": 12,
    "reportCount": 7,
    "reportedAt": "2026-04-20T13:30:00.000Z"
  }'
```

## 验证状态

已经在本地执行通过：

- `npm run test`
- `npm run check`
- `npm run build`
