# OneAuth 项目完整分析与拆解文档

> **项目名称**: OneAuth — 基于 QQ 群验证码的轻量级 OIDC 身份提供商  
> **技术栈**: Go 1.22+ (标准库 + modernc.org/sqlite + golang-jwt/jwt/v5 + gorilla/websocket)  
> **交付物**: 单二进制文件 (`oneauth.exe`) + 嵌入式 WebUI + Docker Compose 配置  

---

## 一、 项目背景与核心需求

### 1.1 业务目标
OneAuth 旨在解决中小型私有 Web 应用（如 Gitea, Nextcloud, Grafana 等）需要集成 QQ 登录，但无法/难以申请官方腾讯开放平台开发者资格的痛点。
通过将“用户在指定 QQ 群内发送 6 位一次性验证码”作为鉴权机制，由 OneBot (NapCatQQ) 反向 WebSocket 捕获群消息，实现 QQ 身份绑定与标准 OIDC 授权码协议签发。

### 1.2 关键约束
1. **纯单二进制**: 前端静态文件（HTML/CSS/JS/图标）全部利用 `//go:embed` 打包，部署零外部依赖。
2. **轻量无外部 DB**: 使用纯 Go 实现的 SQLite (`modernc.org/sqlite`)，开启 WAL 模式；鉴权会话全部常驻内存状态机，零外部 Redis。
3. **协议高兼容**:
   - 严格符合 OIDC Core 1.0 与 RFC 6749，支持 PKCE (S256)。
   - 反向 WebSocket 兼容 OneBot v11 与 OneBot v12 两种报文格式。

---

## 二、 系统架构与数据流拓扑

### 2.1 整体架构图

```
+-----------------------------------------------------------------------------------------+
|                                    OneAuth 进程空间                                     |
|                                                                                         |
|  [ 接入网关层 ]                                                                         |
|  - GET  /.well-known/openid-configuration                                               |
|  - GET  /.well-known/jwks.json                                                          |
|  - GET  /authorize ─── (校验 client_id/redirect_uri) ──► 生成验证码与会话 ──► /login    |
|  - GET  /api/session/stream ──────────► 挂载 SSE 长连接监听状态变更                     |
|  - POST /token ───────────────────────► 校验 AuthCode/PKCE 并签发 RS256 JWT ID Token    |
|  - GET  /userinfo ────────────────────► 解析 Bearer JWT 并响应用户画像                  |
|                                                                                         |
|  [ OneBot 微内核 ]                                                                      |
|  - WS   /ws/onebot ◄── (NapCatQQ 反向 WS) ── 过滤目标群 ── 提取纯文本 ── 正则预筛       |
|                                                     │                                   |
|                                                     ▼                                   |
|  [ 瞬态内存状态机 (In-Memory Hub) ]                 │                                   |
|  - sync.RWMutex 读写互斥锁                          │                                   |
|  - codeIndex: "8K2X9P" ──(原子核销/提取) ◄──────────┘                                   |
|  - 状态广播: 推送 verified 信号至挂起的 SSE 流 ─────► 前端感知并自动跳转                |
|  - 20s 周期性 GC 协程自动驱逐失效会话                                                   |
|                                                                                         |
|  [ 持久化层 (SQLite WAL) ]                                                              |
|  - system_settings: 站点名、背景壁纸、自定义 CSS、目标群号、Bot 连接 Token、TTL          |
|  - oidc_clients: client_id、client_secret_hash、回调地址白名单                          |
|  - admin_users: 管理员用户名与 bcrypt 密码哈希                                          |
+-----------------------------------------------------------------------------------------+
```

### 2.2 认证时序流转

```
用户浏览器                   OneAuth Web/OIDC              OneBot WS 内核             NapCatQQ / QQ群
    |                               |                            |                          |
    | 1. 点击“使用 QQ 登录”          |                            |                          |
    |------------------------------>| (校验 client_id/redirect)  |                          |
    |                               | (生成 SessionID 与 6位 Code)|                          |
    | 2. 302 重定向至 /login        |                            |                          |
    |<------------------------------|                            |                          |
    | 3. 打开登录页并建立 SSE 连接   |                            |                          |
    |==============================>|                            |                          |
    | (展示验证码 "8K2X9P" 与群号)  |                            |                          |
    |                               |                            | 4. 用户在群内发送 "8K2X9P"|
    |                               |                            |<-------------------------|
    |                               | 5. 反向 WS 推送群消息事件   |                          |
    |                               |<---------------------------|                          |
    |                               | (校验群号、清洗文本、原子核销) |                          |
    | 6. SSE 推送跳转指令           |                            |                          |
    |<==============================|                            |                          |
    | 7. 302 回调至业务系统 (code)  |                            |                          |
    |------------------------------>|                            |                          |
    | 8. 业务方后端调用 /token      |                            |                          |
    |------------------------------>| (核销 code, 签发 RS256 JWT)|                          |
    | 9. 返回 id_token (sub=QQ号)   |                            |                          |
    |<------------------------------|                            |                          |
```

---

## 三、 工程模块拆分与职能说明

项目目录组织如下：

```
oneauth/
├── cmd/
│   └── server/
│       └── main.go              # 服务主入口、配置加载、路由装配、HTTP 监听
├── internal/
│   ├── database/
│   │   └── db.go                # SQLite 初始化、WAL 配置、表结构迁移、KV 配置存储
│   ├── session/
│   │   ├── manager.go           # 线程安全会话状态机、验证码原子核销、TTL 过期回收
│   │   └── helpers.go           # 随机 Hex 字符串生成辅助函数
│   ├── oidc/
│   │   └── handler.go           # OIDC 协议端点 (/authorize, /token, /userinfo, JWKS, SSE)
│   ├── onebot/
│   │   └── websocket.go         # OneBot v11/v12 反向 WebSocket 服务端、CQ 码过滤、文本清洗
│   └── admin/
│       └── admin.go             # 管理后台 RESTful API (系统设置、客户端管理、首发初始注册)
├── web/
│   ├── embed.go                 # go:embed 静态资源声明
│   ├── templates/
│   │   ├── login.html           # 毛玻璃拟态风格登录页 (支持 SSE 自动跳转、一键复制、倒计时)
│   │   └── admin.html           # 现代化深色主题 SPA 管理控制台
│   └── static/
│       └── favicon.ico          # 静态图标占位
├── Dockerfile                   # Alpine 多阶段构建配置 (<35MB 极简镜像)
├── docker-compose.yml           # OneAuth + NapCatQQ 联合容器编排
├── README.md                    # 项目快速上手与配置指南
└── 项目分析与拆解文档.md       # 本文档
```

### 3.1 `internal/database` (数据层)
- **职责**: 负责 SQLite 连接管理与基础配置持久化。
- **关键设计**:
  - `PRAGMA journal_mode = WAL;` (开启写前日志，高并发读写不互斥)
  - `PRAGMA busy_timeout = 5000;` (避免并发写冲突时直接报错)
  - `PRAGMA synchronous = NORMAL;` (兼顾性能与掉电安全性)
  - 维护 `system_settings`、`oidc_clients`、`admin_users` 三张表。

### 3.2 `internal/session` (状态机层)
- **职责**: 高频登录验证会话管理。
- **关键设计**:
  - 验证码字符集: `23456789ABCDEFGHJKMNPQRSTUVWXYZ` (去除 0/1/O/I/L 易混淆字符)。
  - 采用 `sync.RWMutex` 保护索引映射，验证码匹配后即时执行 `delete` 原子核销，防重放。
  - 关闭 `NotifyChan` 驱动 SSE 流式连接向浏览器广播跳转信号。
  - 20 秒周期性垃圾回收协程，清除超时未验证或废弃的会话。

### 3.3 `internal/onebot` (机器人事件适配层)
- **职责**: 接收 NapCatQQ 等框架推送的反向 WebSocket 消息。
- **关键设计**:
  - Token 安全认证机制 (Header `Bearer` 或 Query 参数 `access_token`)。
  - 自动识别 OneBot v11 与 v12 双格式。
  - 剥离 `[CQ:at,...]` 等非纯文本标签与转义字符。
  - 使用正则 `^[2-9A-HJ-NP-Z]{6}$` 在微秒级完成普通闲聊与验证码的过滤。

### 3.4 `internal/oidc` (身份认证协议层)
- **职责**: 标准 OIDC 端点提供与 RSA 密钥对生命周期管理。
- **关键设计**:
  - 首次运行自动生成 2048 位 RSA 密钥并持久化为 PEM 格式文件。
  - 公钥指纹生成唯一 `kid` 并提供 `/.well-known/jwks.json`。
  - `/token` 支持 Authorization Code 模式及 PKCE S256 校验。
  - 签发标准的 RS256 JWT，映射 QQ 号至 `sub`, `email` (`{qq}@qq.com`), `picture` 等 Claims。

### 3.5 `internal/admin` (运维管理层)
- **职责**: 提供系统级参数配置与 OIDC 客户端管理能力。
- **关键设计**:
  - 密码使用 `bcrypt` 单向散列加密。
  - 客户端密钥在创建时通过 SHA-256 散列入库，明文仅展示一次。
  - 具备首次启动无账号时的引导注册逻辑 (`/api/admin/setup`)。

---

## 四、 编译与交付验证

本项目已完成全量源码编写与静态编译验证：
1. **源码编译测试**: 采用 Go 1.22+ 编译生成 `oneauth.exe`，大小约为 19.9 MB。
2. **零外部运行依赖**: 静态文件全部集成在二进制内部。
3. **已支持环境配置**:
   - `PORT`: 监听端口（默认 `9000`）
   - `DB_PATH`: SQLite 数据库落盘路径（默认 `oneauth.db`）
   - `KEY_PATH`: RSA 私钥存储路径（默认 `oneauth_rsa.pem`）
