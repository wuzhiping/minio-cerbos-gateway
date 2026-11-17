# MinIO + Cerbos Authorization Gateway

通用 MinIO Object 读取授权网关。Bucket 不设白名单；未认证请求默认以
`anonymous` 身份调用 Cerbos。只有 PDP 明确返回 `EFFECT_ALLOW` 才访问 MinIO。

## 功能范围

- `GET /{bucket}/{object_key}`：对象读取，支持 HTTP Range。
- `HEAD /{bucket}/{object_key}`：对象元数据读取。
- 任意 Bucket，不在代码中硬编码 bucket allowlist。
- 未提供可信身份时使用 `principal.id=anonymous`、`roles=["anonymous"]`。
- Cerbos 超时、异常或响应异常时 Fail Closed（503）。
- 不实现 PUT、DELETE、ListObjectsV2；这些操作必须分别增加动作和授权检查。

## 目录

```text
app/main.py
policies/resource_policies/minio_object.yaml
policies/resource_policies/aife.yaml
policies/resource_policies/dsh.yaml
Dockerfile
compose.yaml
.env.example
requirements.txt
```

## 启动

1. 将本目录的 `policies/` 部署到 Cerbos PDP（`POST /admin/policy`，请求体
   `{"policies": [<策略文档>]}`），或合并到 PDP 的策略目录。
2. 按需修改 `.env.example`（`compose.yaml` 直接以它作为 `env_file`，默认配置即可运行）：
   Cerbos 地址、MinIO endpoint、bucket→资源名映射、路径前缀、MinIO 凭据（见“MinIO 访问模式”）。
3. `docker compose up -d --build`

### 配置来源与优先级

Gateway 自身会读取项目根目录的 `.env.example`（以及可选的 `.env`），因此脱离
compose 直接运行也能生效。优先级从高到低：

1. 进程环境变量
2. `.env`
3. `.env.example`
4. 代码内置默认值

默认 `MINIO_ENDPOINT` 为 `https://oss.feg.cn`，默认 `MINIO_SECURE` 留空并跟随 endpoint
协议（`https://` → `true`，`http://` → `false`）；显式设置 `MINIO_SECURE` 时以显式值为准。

默认 Cerbos 与 MinIO 都是外部服务（`http://10.17.1.201:3592`、`https://oss.feg.cn`），
容器不依赖任何外部 Docker 网络；若把 MinIO / Cerbos 改为同机容器，需在
`compose.yaml` 中补回 `networks` 并把两者加入同一网络。

Gateway 默认监听 `0.0.0.0:8088`（`compose.yaml` 中 `"8088:8080"`）。Gateway 完全信任
`X-Auth-*` 身份头，因此**必须**由防火墙/安全组限制只有可信反向代理能访问该端口，
否则任何能连上的人都可以自行声明身份（如 `X-Auth-Roles: admin`）。
如需仅本机访问，把端口映射改为 `"127.0.0.1:8088:8080"`。

### 路径前缀

`root_path` 决定网关挂载的路径前缀，默认 `/share/s3`（来自 `.env.example`，
取值带不带前导斜杠均可）。带前缀与不带前缀的 URL 都会被正确路由，例如
`/share/s3/aife/4KI/STORY.html` 与 `/aife/4KI/STORY.html` 等价，
Swagger 文档位于 `/share/s3/docs`。

## Policy 示例

策略按「资源名」划分，一个文件一个资源名（不使用 scope）：

| 策略文件 | 资源名 | 适用 bucket | anonymous |
|----------|--------|-------------|-----------|
| `minio_object.yaml` | `minio_object` | 未单独配置策略的 bucket | 仅 `public/` 前缀 |
| `aife.yaml` | `aife` | `aife` | 整个 bucket 全部可读 |
| `dsh.yaml` | `dsh` | `dsh` | 整个 bucket 全部可读 |

每个策略都包含三类角色：

- anonymous：`aife`/`dsh` 为整个 bucket 全部可读；`minio_object` 仅允许 `public/` 前缀。
- user：只允许 `X-Auth-Path-Prefix` 指定前缀下的对象。
- admin：允许读取任意对象。
- 未命中 allow 规则：Cerbos 默认拒绝。

Gateway 按 bucket 选择资源名，由 `CERBOS_BUCKET_KINDS` 决定（格式 `bucket=kind`），
未列出的 bucket 使用 `CERBOS_RESOURCE_KIND`（默认 `minio_object`）：

```bash
CERBOS_BUCKET_KINDS=aife=aife,dsh=dsh
CERBOS_RESOURCE_KIND=minio_object
```

映射到的资源名必须在 PDP 中存在对应策略，否则该 bucket 的请求会被 Cerbos 拒绝
（未知资源名返回 `EFFECT_DENY`，网关表现为 403）。
部署策略：`POST /admin/policy`，请求体为 `{"policies": [<策略文档>]}`。

例如 anonymous 可以读取：

`GET /aife/public/index.html`（minio_object 规则）

`GET /aife/4KI/STORY.html`（aife 规则，整桶可读）

anonymous 不能读取（bucket 未配置专用策略时）：

`GET /other/4KI/STORY.html`

## 身份头安全要求

`X-Auth-User`、`X-Auth-Roles`、`X-Auth-Org`、`X-Auth-Path-Prefix`
只能由可信认证代理设置。Nginx 必须清除客户端传入的同名 Header，再通过
OIDC/auth_request 等可信机制注入身份。不要让用户能够直接访问 Gateway 端口。

未提供 `X-Auth-User` 时，Gateway 使用 anonymous。提供用户身份但未提供角色时，
默认角色为 `user`。生产环境应由认证代理提供角色和 path prefix，不能允许用户自行指定。

## 客户端 IP

Gateway 会把客户端 IP 放入 `principal.attr.ip`，策略中可用
`request.principal.attr.ip` 做条件判断。

取值顺序：请求头 `X-Forwarded-For` 的第一段 → TCP 对端地址（`request.client.host`）。
由于 `X-Forwarded-For` 可被客户端伪造，可信代理必须**覆盖**该头
（Nginx 用 `proxy_set_header X-Forwarded-For $remote_addr;`，不要用会追加的
`$proxy_add_x_forwarded_for`），否则 IP 条件可被绕过。

## MinIO 访问模式

Gateway 支持两种访问 MinIO 的方式，由环境变量决定：

| 模式 | 条件 | 说明 |
|------|------|------|
| 签名访问 | `MINIO_ACCESS_KEY` 与 `MINIO_SECRET_KEY` 都非空 | Gateway 用该账号签名访问 MinIO |
| 匿名访问 | 上述两项为空（或只填了一项） | Gateway 发送 unsigned 请求，MinIO 按自身桶策略判定 |

- 匿名模式下不发送 `Authorization` 头，MinIO 侧必须另行给桶配置匿名读策略
  （例如允许 `public/` 前缀匿名 GET/HEAD），否则 MinIO 返回 `AccessDenied`，
  Gateway 转为 `403 Access denied by storage backend`；其余存储错误转为
  `502 Storage backend error`。
- 只填了 access key 或只填了 secret key 时同样按匿名访问处理，并打印告警日志。
- 两种模式下 Cerbos 授权流程完全一致：是否允许访问由策略决定，与 MinIO 凭据无关。

## 性能与并发

### 架构要点

- 所有对 MinIO 的调用都是阻塞式的（boto3），因此**不能**在事件循环里直接调用。
  网关用 `anyio.to_thread.run_sync` 把 `head_object` / `get_object` / `body.read`
  放进线程池，事件循环因此不会被传输中的大文件阻塞。
- 流式输出是**异步** generator，每个分块只在读取瞬间占用一个线程池令牌
  （同步 generator 会让每次传输独占一个令牌，默认上限 40/worker）。
- 每个 worker 是独立进程，各自持有 boto3 连接池与 Cerbos HTTP 连接池。

### 可调参数

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `STREAM_CHUNK_SIZE` | `524288` | 流式分块大小（字节） |
| `MINIO_MAX_POOL_CONNECTIONS` | `32` | boto3 连接池（默认只有 10） |
| `THREADPOOL_TOKENS` | `128` | 每 worker 的阻塞调用线程池上限 |
| `CERBOS_MAX_CONNECTIONS` | `100` | 到 Cerbos 的最大并发连接 |
| `CACHE_CONTROL` | `private, max-age=300` | 浏览器缓存策略 |
| `ACCESS_LOG` | `true` | 输出分阶段耗时访问日志 |

worker 数由 Dockerfile 的 `--workers 4` 决定（IO 密集型，按 CPU 调整）。

### 访问日志

每个对象请求输出一行，可据此区分"网关慢"还是"后端慢"：

```
rid=0d939c0b282e GET dsh/12601-flbzu8.mp4 status=206 cerbos_ms=11.6 minio_ms=273.4 total_ms=422.3 bytes=1024 ip=127.0.0.1
```

`rid` 同时写入响应头 `X-Request-ID`，客户端可自带该头以便全链路追踪。

### 缓存与条件请求

- `CACHE_CONTROL` 决定浏览器缓存；默认 `private, max-age=300`，
  MP4 重复播放/拖动进度条可直接命中浏览器缓存，不再回源。
  **代价**：权限撤销后客户端缓存最多 `max-age` 秒内仍可能命中。
  设为 `no-store` 可回到"完全不缓存"。
- 支持 `If-None-Match` → 命中 ETag 返回 **304**（不下发 body）。
- 支持 `If-Range` → ETag 不匹配时忽略 Range 改发完整对象。
- Range 不可满足时返回 **416**。

### 性能实测（本机 → `oss.feg.cn`，us-west-rack-2）

| 场景 | 改造前 | 改造后 |
|------|--------|--------|
| 8 并发 × 1MB | 2443ms | **1035ms**（4 workers）/ 1296ms（1 worker） |
| 16 并发 × 1MB | 4037ms | **1637ms**（4 workers）/ 1585ms（1 worker） |

**后端链路是硬上限**：实测 Cerbos 授权往返仅 ~2ms，但对象存储单请求 TTFB ~100ms
（连 1 字节 Range 也是 101ms），整机出口带宽约 **7MB/s**，且 8/16/32 并发下吞吐
都不再上升。网关自身的开销已被消除，再加并发也不会更快；
MP4 的体感提速主要来自浏览器缓存命中。

## Nginx 代理示例

```nginx
# 路径前缀与 Gateway 的 root_path 保持一致（默认 /share/s3）
location /share/s3/ {
    # 此处应先执行真实认证；以下变量应由认证子请求返回。
    auth_request /_auth;
    auth_request_set $auth_user $upstream_http_x_auth_user;
    auth_request_set $auth_roles $upstream_http_x_auth_roles;
    auth_request_set $auth_prefix $upstream_http_x_auth_path_prefix;

    proxy_set_header X-Auth-User $auth_user;
    proxy_set_header X-Auth-Roles $auth_roles;
    proxy_set_header X-Auth-Path-Prefix $auth_prefix;

    # 覆盖客户端传入的 X-Forwarded-For，Gateway 据此设置 principal.attr.ip。
    proxy_set_header X-Forwarded-For $remote_addr;

    # 不透传客户端伪造的身份头；由上面的可信变量覆盖。
    proxy_pass http://127.0.0.1:8088;
}
```

上面是接入示意，`/_auth` 必须由实际认证系统实现；不能直接照搬为空认证端点。

## 测试

匿名请求（`aife`/`dsh` 为整桶可读）：

```bash
curl -i http://127.0.0.1:8088/share/s3/aife/4KI/STORY.html
curl -i http://127.0.0.1:8088/share/s3/dsh/4KI/HANDOFF.md
```

未配置专用策略的 bucket 只有 `public/` 前缀可访问：

```bash
curl -i http://127.0.0.1:8088/share/s3/other/public/index.html
```

认证用户示例（仅在可信代理正确注入身份时使用）：

```bash
curl -i \
  -H 'X-Auth-User: alice' \
  -H 'X-Auth-Roles: user' \
  -H 'X-Auth-Path-Prefix: 4KI/' \
  http://127.0.0.1:8088/share/s3/aife/4KI/STORY.html
```

## 生产注意事项

- MinIO 原始 S3 API 不应对终端用户开放；网络层确保只能经 Gateway 访问。
- 签名模式下 MinIO 凭据使用独立的最小权限只读 Service Account；匿名模式下依赖桶策略收敛读范围。
- 当前实现是对象读取网关，不是完整 S3 API 兼容代理。
- ListObjects、写入、删除、预签名 URL、multipart upload 等必须单独设计授权。
- 生产部署建议补充 JWT/OIDC 验证、审计日志、速率限制、并发控制和对象大小限制。
