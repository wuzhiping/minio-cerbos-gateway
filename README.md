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
Dockerfile
compose.yaml
.env.example
requirements.txt
```

## 启动

1. 将本目录的 `policies/` 合并到 Cerbos PDP 的策略目录。
2. 确认 Cerbos 与 MinIO 容器都加入 Docker 网络 `storage`，或修改 `compose.yaml`
   中网络名称。
3. `cp .env.example .env`，填写 MinIO 专用只读账号及正确 endpoint。
4. `docker compose up -d --build`

Gateway 绑定 `127.0.0.1:8088`，建议由 Nginx 在本机反向代理，不要直接暴露公网。

## Policy 示例

- anonymous：允许任意 Bucket 中 `public/` 前缀下的对象。
- user：只允许 `X-Auth-Path-Prefix` 指定前缀下的对象。
- admin：允许读取任意对象。
- 未命中 allow 规则：Cerbos 默认拒绝。

例如 anonymous 可以读取：

`GET /aife/public/index.html`

anonymous 不能读取：

`GET /aife/4KI/STORY.html`

## 身份头安全要求

`X-Auth-User`、`X-Auth-Roles`、`X-Auth-Org`、`X-Auth-Path-Prefix`
只能由可信认证代理设置。Nginx 必须清除客户端传入的同名 Header，再通过
OIDC/auth_request 等可信机制注入身份。不要让用户能够直接访问 Gateway 端口。

未提供 `X-Auth-User` 时，Gateway 使用 anonymous。提供用户身份但未提供角色时，
默认角色为 `user`。生产环境应由认证代理提供角色和 path prefix，不能允许用户自行指定。

## Nginx 代理示例

```nginx
location / {
    # 此处应先执行真实认证；以下变量应由认证子请求返回。
    auth_request /_auth;
    auth_request_set $auth_user $upstream_http_x_auth_user;
    auth_request_set $auth_roles $upstream_http_x_auth_roles;
    auth_request_set $auth_prefix $upstream_http_x_auth_path_prefix;

    proxy_set_header X-Auth-User $auth_user;
    proxy_set_header X-Auth-Roles $auth_roles;
    proxy_set_header X-Auth-Path-Prefix $auth_prefix;

    # 不透传客户端伪造的身份头；由上面的可信变量覆盖。
    proxy_pass http://127.0.0.1:8088;
}
```

上面是接入示意，`/_auth` 必须由实际认证系统实现；不能直接照搬为空认证端点。

## 测试

匿名请求（根据策略，只有 public/ 可访问）：

```bash
curl -i http://127.0.0.1:8088/aife/public/index.html
curl -i http://127.0.0.1:8088/aife/4KI/STORY.html
```

认证用户示例（仅在可信代理正确注入身份时使用）：

```bash
curl -i \
  -H 'X-Auth-User: alice' \
  -H 'X-Auth-Roles: user' \
  -H 'X-Auth-Path-Prefix: 4KI/' \
  http://127.0.0.1:8088/aife/4KI/STORY.html
```

## 生产注意事项

- MinIO 原始 S3 API 不应对终端用户开放；网络层确保只能经 Gateway 访问。
- MinIO 凭据使用独立的最小权限只读 Service Account。
- 当前实现是对象读取网关，不是完整 S3 API 兼容代理。
- ListObjects、写入、删除、预签名 URL、multipart upload 等必须单独设计授权。
- 生产部署建议补充 JWT/OIDC 验证、审计日志、速率限制、并发控制和对象大小限制。
