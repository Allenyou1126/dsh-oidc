# dsh-oidc

DeepSeek Harness 0.2.3-alpha.2 的最小 OIDC SSO 插件：用 **Zitadel Web + PKCE（无 client secret）** 登录 Web GUI，替代 Remote Connection 的登录入口，不再需要 oauth2-proxy 等 OAuth 反向代理。

- 自定义 `AuthenticationProvider`：校验签名 Cookie 后返回共享 owner Peer。
- Authorization Code + PKCE(S256)，token 交换不发送 `Authorization` / `client_secret`。
- RS256 ID Token 校验；角色兜底只依赖一个可配置 claim（如 `roles` 或 Zitadel 的 `urn:zitadel:iam:org:project:roles`）。
- 不做邮箱/域名白名单、userinfo、refresh、end_session、二维码/配对、API Bearer Token。
- 被允许的 SSO 用户拥有 **owner** 权限；DSH 0.2.3 只有 owner 这一种内置 Principal。

## 前提

- DSH `0.2.3-alpha.2`，Web profile。
- Zitadel 中创建 **Web** 应用，Authentication method 选 **PKCE**；确认摘要为 `Authentication Method: None`，**没有 client secret**。
  - 不要选 `Code` / `POST` / `(Private Key) JWT`：这些需要 secret 或 key，本插件不发送。
  - 现有给 oauth2-proxy 用的 Web 应用通常是 Code/Basic（有 secret），不要直接复用；给 DSH 新建一个 Web+PKCE 应用，或在 oauth2-proxy 下线后再切换。
- 公开部署使用 HTTPS；DSH 启动参数包含 `--public-url` 和 `--trusted-host`，反向代理保留 Host、剥离路径前缀（如有）并转发 Upgrade。
- 迁移期保留 token URL 或 Remote Connection 作为回退；确认 SSO 正常后再禁用 Remote Connection。

## 安装

```sh
# 从 GitHub 安装
dsh plugin --profile <profile> add github:Allenyou1126/dsh-oidc

# 或安装本地 checkout
dsh plugin --profile <profile> add /absolute/path/to/dsh-oidc
```

或在 **Plugins → Add plugin** 填写 `github:Allenyou1126/dsh-oidc` 或选择本地目录。安装后插件行出现；未设置 `DSH_OIDC_ISSUER` / `DSH_OIDC_CLIENT_ID` 时保持 inactive，不拦截任何请求。

## 配置

配置优先读插件行 Config；空值回退环境变量。最简只需要 issuer + clientId；角色兜底可选。

| 字段 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `issuer` | `DSH_OIDC_ISSUER` | 空 | Zitadel issuer，如 `https://auth.example.com`；HTTPS |
| `clientId` | `DSH_OIDC_CLIENT_ID` | 空 | Zitadel Web+PKCE 应用的 Client ID；无 secret |
| `scopes` | `DSH_OIDC_SCOPES` | `openid` | 空格/逗号分隔；角色需要额外 scope，见下 |
| `roleClaim` | `DSH_OIDC_ROLE_CLAIM` | 空 | 可选；空 = 不额外限制 |
| `allowedRoles` | `DSH_OIDC_ALLOWED_ROLES` | 空 | 逗号分隔；`roleClaim` 有值但这里为空时，只要求该 claim 至少有一个值 |
| `enabled` | `DSH_OIDC_ENABLED` | true | `0` 为紧急停用 |

示例：

```sh
DSH_OIDC_ISSUER=https://auth.example.com
DSH_OIDC_CLIENT_ID=340123456789012345
DSH_OIDC_SCOPES="openid urn:zitadel:iam:org:project:id:340123456789012345:aud"
DSH_OIDC_ROLE_CLAIM="urn:zitadel:iam:org:project:roles"
DSH_OIDC_ALLOWED_ROLES="dsh-owner"
```

改 env 后需要重启 DSH 进程（process.env 不会热更新）。也可以把同样的字段写进 profile 的 `cordis.patch.yml` 覆盖该行 Config。

### 访问兜底

```text
roleClaim 为空：允许任何通过 IdP 登录的用户
roleClaim 有值：
  - 取该 claim（先精确 key，再点号路径）
  - 数组 → 字符串值；对象 → 键（Zitadel roles 是对象）；字符串 → 单值
  - claim 为空 → 403
  - allowedRoles 为空 → 允许
  - 与 allowedRoles 有交集 → 允许，否则 403
```

- 不读取 email，不做邮箱/域名匹配。
- 角色值精确匹配、区分大小写。
- 在回调时判断一次；session 12 小时内不再查 IdP。配置变更会重载插件并更换随机签名 key，旧 session 失效。
- 不配置 `roleClaim` 时，任何能通过 IdP 认证的用户都是 owner；请确认 IdP 应用本身的可登录范围。

## Zitadel 配置

1. 在 Project 下 **New Application**，类型选 **Web**。
2. Authentication method 选 **PKCE**（推荐，摘要显示 `Authentication Method: None`）。
3. Redirect URI 填 `https://dsh.example.com/auth/callback`；路径前缀部署时填对应前缀。只本地 HTTP 测试才开 Development mode。
4. 创建后复制 **Client ID**；不要配置 client secret。
5. 如需角色兜底：
   - 在应用的 Token Settings 中启用把 **User Roles** 放进 ID Token；
   - 请求 project audience scope：`urn:zitadel:iam:org:project:id:<project-id>:aud`；
   - 把 `DSH_OIDC_ROLE_CLAIM` 设为 `urn:zitadel:iam:org:project:roles`，`DSH_OIDC_ALLOWED_ROLES` 设为角色 key。
6. 如果角色值在嵌套路径（例如 Keycloak 的 `realm_access.roles`），直接把该点号路径填入 `roleClaim`。

## 运行行为

- 未登录访问 `/`（或 `/index.html`）且是 HTML 导航 → 302 到 `/auth/login`，再 302 到 IdP。
- IdP 回调 `GET /auth/callback` 在 DSH 的来源围栏之前处理；允许跨站顶层导航，但要求签名 state Cookie、PKCE、nonce、Host 匹配。
- 成功后设置 `dsh-oidc-session` Cookie，并返回一个同源完成页，由页面脚本跳回应用，避免 DSH 对跨站 `Sec-Fetch-Site` 的 403。
- `GET /auth/logout` 清除浏览器 Cookie；不做 IdP 单点登出。跨站登出被拒绝。
- Cookie：`HttpOnly`、`SameSite=Lax`、HTTPS 下 `Secure`、12 小时；session 签名 key 在插件激活时随机生成，不落盘。

## 禁用 Remote Connection

确认 SSO 正常后，在 profile 的 `cordis.patch.yml` 追加：

```yaml
- id: remote-connection
  disabled: true
```

或在 Plugins 页面禁用 Remote Connection 行。禁用后：

- 二维码、配对审批、Remote connection 设置页消失（本插件不替代这些 UI）；
- `/` 由本插件重定向到 IdP；
- 已签发的 Remote Cookie 不再被认证；
- token 启动 URL 仍可用（除非同时禁用 `authentication-token`），可作为应急入口。

## 安全与限制

- 无 client secret：依赖 Zitadel Web+PKCE（Auth Method None）的 public client 配置；如果应用是 Code/Post/JWT，token 交换会失败。
- 所有被允许用户都是 owner：可执行工具、读写工作区、安装插件；只适合单用户/可信部署。
- 无服务端 session 吊销：登出只清浏览器 Cookie，已复制的 Cookie 在 12 小时内仍有效；要全部失效，重启 DSH/重载插件。
- DSH 重启/插件重载后随机签名 key 变化，所有 session 失效，浏览器会静默重走 IdP SSO（前提是 IdP 会话仍有效）。
- 仅 RS256；仅 OIDC discovery；不支持 userinfo 补 claims、refresh token、IdP end_session、form_post、多用户权限、API Bearer Token。
- 角色信息必须已经在 ID Token 中；如果只在 userinfo 里，需要使用 IdP 的 token 设置把它放进 ID Token，或后续扩展。
- Cookie 是签名不是加密，内容仅 sub/host/时间，不含 email/token/secret。

## 排障

| 现象 | 检查 |
|---|---|
| `/auth/login` 404/401 | 插件是否 active：issuer/clientId 是否设置、`DSH_OIDC_ENABLED` 是否 `0`；DSH 日志中是否有 `dsh-oidc: inactive` |
| 回调 403 `Request host ...` | `--public-url` 的 host 是否等于浏览器 Host；代理是否保留 Host；`--trusted-host` 是否包含该 host |
| 回调 400 `state expired` | 重新从 `/` 开始；多标签页同时登录时后发起的会覆盖 state Cookie |
| 502 / discovery failed | DSH 机器能否访问 issuer；issuer 是否与 discovery 的 `issuer` 完全一致（协议/host/路径） |
| token 交换失败 | Zitadel 应用是否 **Web + PKCE**（Auth Method None）；redirect URI 是否精确匹配；是否误用了 Code/Post/JWT |
| 403 `not allowed` | `roleClaim` 是否存在于 ID Token；scope/Token Settings 是否把角色放进 ID Token；`allowedRoles` 是否精确匹配（Zitadel 对象 key） |
| 登录后回到 401/403 | Cookie `Secure` 与公开 HTTPS 是否一致；代理是否改写 Host；浏览器是否禁用了 Cookie |
| 想完全退出 SSO | 在 IdP 侧登出；本插件不调用 end_session |

## 开发

```sh
node --check src/*.js test/*.js
node --test test/*.test.js
```

测试使用本地 mock OIDC provider，覆盖 public-client token 交换（无 Authorization）、PKCE、RS256、JWKS 轮换、roleClaim、完整登录/登出链路。
