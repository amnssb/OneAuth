package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"oneauth/internal/admin"
	"oneauth/internal/database"
	"oneauth/internal/identity"
	"oneauth/internal/oidc"
	"oneauth/internal/onebot"
	"oneauth/internal/session"
	"oneauth/web"
)

func main() {
	port := getEnv("PORT", "9000")
	dbPath := getEnv("DB_PATH", "oneauth.db")
	keyPath := getEnv("KEY_PATH", "oneauth_rsa.pem")

	if _, err := database.InitDB(dbPath); err != nil {
		log.Fatalf("[启动失败] 数据库初始化异常: %v", err)
	}

	oidc.InitKeys(keyPath)

	mux := http.NewServeMux()

	// OIDC 协议端点
	oidc.RegisterRoutes(mux)

	// 管理后台 API
	admin.RegisterRoutes(mux)

	// OneBot 反向 WebSocket
	mux.HandleFunc("/ws/onebot", onebot.HandleWebSocket)

	// 嵌入式前端资源
	tmplFS, err := fs.Sub(web.EmbeddedFS, "templates")
	if err != nil {
		log.Fatalf("[启动失败] 模板文件系统初始化异常: %v", err)
	}
	staticFS, err := fs.Sub(web.EmbeddedFS, "static")
	if err != nil {
		log.Fatalf("[启动失败] 静态资源文件系统初始化异常: %v", err)
	}

	loginTmpl := template.Must(template.ParseFS(tmplFS, "login.html"))
	adminTmpl := template.Must(template.ParseFS(tmplFS, "admin.html"))

	// 静态资源服务
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// 登录页面：品牌按发起登录的客户端逐项覆盖（display_name/background_url/
	// prompt_text/custom_css），未设置的字段回落到全局设置 —— 同一个 OneAuth
	// 服务多个项目时，各项目呈现各自的登录页。
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		sess, exists := session.DefaultManager.GetSession(sessionID)
		if !exists {
			http.Error(w, "会话不存在或已过期", http.StatusBadRequest)
			return
		}

		branding := database.GetClientBranding(sess.ClientID)
		siteName := branding["display_name"]
		if siteName == "" {
			siteName = database.GetSetting("site_name", "统一身份认证中心")
		}
		background := branding["background_url"]
		if background == "" {
			background = database.GetSetting("background_url", "")
		}
		prompt := branding["prompt_text"]
		if prompt == "" {
			prompt = database.GetSetting("prompt_text", "请发送验证码至群")
		}
		customCSS := branding["custom_css"]
		if customCSS == "" {
			customCSS = database.GetSetting("custom_css", "")
		}

		ttlStr := database.GetSetting("code_ttl", "180")
		ttl, _ := strconv.Atoi(ttlStr)

		data := map[string]interface{}{
			"SessionID":     sess.SessionID,
			"VerifyCode":    sess.VerifyCode,
			"GroupID":       database.GetSetting("target_group_id", ""),
			"SiteName":      siteName,
			"PromptText":    prompt,
			"BackgroundURL": background,
			"CustomCSS":     template.CSS(customCSS),
			"TTL":           ttl,
			// 登录页当前仅 QQ 一条核销通道；多平台接入后这里按会话可用的
			// 通道动态展示各平台说明。
			"PlatformLabel": identity.Label(identity.ProviderQQ),
		}
		if err := loginTmpl.Execute(w, data); err != nil {
			log.Printf("[模板渲染] 登录页渲染失败: %v\n", err)
		}
	})

	// 管理后台页面
	mux.HandleFunc("GET /admin", admin.SecureHeaders(func(w http.ResponseWriter, r *http.Request) {
		if err := adminTmpl.Execute(w, nil); err != nil {
			log.Printf("[模板渲染] 管理后台渲染失败: %v\n", err)
		}
	}))

	// 预置或确保 Demo 测试应用存在（是否对外可访问由 demo_enabled 开关控制）
	initDemoClient()

	// 多 Issuer 强制迁移：打印各应用当前的 issuer_slug 与发现地址，提醒
	// 接入方把配置改到 https://<host>/{slug}/.well-known/openid-configuration。
	logTenantIssuers(port)

	// 根路径：始终展示 OneAuth 首页，不再依赖 Demo 是否启用
	mux.HandleFunc("GET /{$}", handleHomePage)

	// 内置测试 Demo 应用主页 / OAuth2 回调端点：受 demo_enabled 开关控制，
	// 关闭时对外表现为 404（而非报错或跳转），避免暴露内部状态。
	mux.HandleFunc("GET /demo", demoGuard(handleDemoPage))
	mux.HandleFunc("GET /demo/callback", demoGuard(handleDemoCallback))

	log.Printf("🚀 OneAuth 已启动 → http://0.0.0.0:%s\n", port)
	log.Printf("📋 管理后台 → http://localhost:%s/admin\n", port)
	log.Printf("🔗 OIDC 发现（多 Issuer）→ http://localhost:%s/{issuer_slug}/.well-known/openid-configuration\n", port)
	log.Printf("🤖 OneBot WS → ws://localhost:%s/ws/onebot\n", port)

	// 显式配置 Server：ReadHeaderTimeout 防 Slowloris 慢连接占用；
	// 不设 WriteTimeout（会掐断 SSE 长连接），空闲回收交给 IdleTimeout。
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           oidc.Wrap(mux), // 首段非固定路由的请求分流到租户端点
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       75 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// 优雅停机：等待在途请求（含 SSE 等待核销的长连接）最多 10s
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		log.Println("🛑 收到退出信号，正在优雅停机...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("[停机] 强制退出: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[启动失败] HTTP 服务异常: %v", err)
	}
	log.Println("OneAuth 已停止")
}

// callbackClient 供 demo 回调自调用 /token 使用：复用 TCP 连接，
// 避免 http.PostForm 默认 Transport 每次新建连接。
var callbackClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	},
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

const (
	demoClientID     = "oneauth_demo_app"
	demoClientSecret = "demo_secret_888888"
	demoIssuerSlug   = "demo-app"
)

// demoGuard 用 demo_enabled 系统设置包裹 demo 相关 handler：关闭时统一
// 返回 404，不泄露 demo 路由是否存在，也不影响其余路由的正常访问。
func demoGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if database.GetSetting("demo_enabled", "true") != "true" {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// handleHomePage 是根路径 "/" 的固定首页：不依赖 Demo 开关，始终可访问，
// 展示站点基本信息并按需引导到登录/管理后台/Demo 体验入口。
func handleHomePage(w http.ResponseWriter, r *http.Request) {
	siteName := database.GetSetting("site_name", "统一身份认证中心")
	demoOn := database.GetSetting("demo_enabled", "true") == "true"

	demoBlock := ""
	if demoOn {
		demoBlock = `
        <a class="btn-primary" href="/demo">
            <span>🚀 体验 Demo 接入应用</span>
        </a>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.SiteName}}</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: #060813;
            color: #94a3b8;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .home-card {
            background: rgba(19, 26, 53, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(28px);
            border-radius: 28px;
            padding: 48px 40px;
            max-width: 520px;
            width: 100%;
            text-align: center;
            box-shadow: 0 30px 80px rgba(0,0,0,0.6);
        }
        .home-badge {
            display: inline-block;
            background: rgba(0, 212, 255, 0.15);
            color: #00d4ff;
            border: 1px solid rgba(0, 212, 255, 0.3);
            font-size: 0.75rem;
            font-weight: 700;
            padding: 4px 12px;
            border-radius: 20px;
            margin-bottom: 20px;
            text-transform: uppercase;
        }
        h1 { font-size: 1.9rem; font-weight: 800; color: #f8fafc; margin-bottom: 12px; }
        p { font-size: 0.95rem; line-height: 1.6; margin-bottom: 28px; }
        .btn-primary, .btn-secondary {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: 100%;
            padding: 15px 28px;
            border-radius: 14px;
            text-decoration: none;
            font-size: 1.02rem;
            font-weight: 700;
            transition: all 0.25s;
            margin-bottom: 14px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #00d4ff 0%, #0066ff 100%);
            color: #000;
            box-shadow: 0 10px 28px rgba(0, 212, 255, 0.35);
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 14px 34px rgba(0, 212, 255, 0.5);
            filter: brightness(1.08);
        }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.06);
            color: #cbd5e1;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .btn-secondary:hover { background: rgba(255, 255, 255, 0.12); }
    </style>
</head>
<body>
    <div class="home-card">
        <span class="home-badge">OpenID Connect Provider</span>
        <h1>{{.SiteName}}</h1>
        <p>基于 OIDC 协议的统一身份认证服务，为接入的业务系统提供群验证码单点登录能力。</p>
        {{.DemoBlock}}
        <a class="btn-secondary" href="/admin">⚙️ 进入管理员控制台</a>
    </div>
</body>
</html>`
	html = strings.Replace(html, "{{.SiteName}}", template.HTMLEscapeString(siteName), -1)
	html = strings.Replace(html, "{{.DemoBlock}}", demoBlock, 1)
	_, _ = w.Write([]byte(html))
}

func initDemoClient() {
	h := sha256.Sum256([]byte(demoClientSecret))
	secretHash := base64.RawURLEncoding.EncodeToString(h[:])
	// 多 Issuer 强制迁移后 demo 应用也必须有独立 slug，固定为 demo-app；
	// 冲突处理交给 issuer_slug 唯一索引（demo-app 是保留给内置应用的固定值）。
	_, _ = database.WriteDB.Exec(`
		INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug)
		VALUES (?, ?, 'OneAuth 内置体验应用', 'http://localhost:9000/demo/callback,http://127.0.0.1:9000/demo/callback', ?)
		ON CONFLICT(client_id) DO UPDATE SET redirect_uris = excluded.redirect_uris, issuer_slug = excluded.issuer_slug
	`, demoClientID, secretHash, demoIssuerSlug)
}

// logTenantIssuers 在启动时打印每个已注册应用的 issuer_slug 与本地发现
// 地址，作为多 Issuer 强制迁移的破坏性变更提示：接入方需据此更新配置。
func logTenantIssuers(port string) {
	rows, err := database.DB.Query("SELECT client_name, COALESCE(issuer_slug, '') FROM oidc_clients ORDER BY created_at")
	if err != nil {
		log.Printf("[启动] 读取应用 Issuer 列表失败: %v", err)
		return
	}
	defer rows.Close()

	log.Printf("🏷️  多 Issuer 已启用，各应用发现地址如下（接入方请更新配置）：")
	any := false
	for rows.Next() {
		var name, slug string
		if err := rows.Scan(&name, &slug); err != nil {
			continue
		}
		any = true
		if slug == "" {
			log.Printf("   - %s：⚠️ 未分配 issuer_slug（异常，请在后台补齐）", name)
			continue
		}
		log.Printf("   - %s → http://localhost:%s/%s/.well-known/openid-configuration", name, port, slug)
	}
	if !any {
		log.Printf("   （暂无注册应用）")
	}
}

// currentScheme 与 getBaseURL 同规则：反代告知 https 或原生 TLS 时用 https。
func currentScheme(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}

// demoRedirectMu 串行化演示客户端回调地址的“读-拼-写”，避免并发渲染
// 时互相覆盖追加结果。
var demoRedirectMu sync.Mutex

// registerDemoRedirectURI 把当前访问来源的回调地址并入演示客户端的注册
// 列表。演示页的 redirect_uri 必须与浏览器实际地址一致 —— 否则核销后的
// 授权码会被送到别处（例如用户本机也跑着一个 OneAuth 的 localhost:9000），
// /token 换取时就会 invalid_grant。
func registerDemoRedirectURI(callback string) {
	demoRedirectMu.Lock()
	defer demoRedirectMu.Unlock()

	var uris string
	if err := database.DB.QueryRow("SELECT redirect_uris FROM oidc_clients WHERE client_id = ?", demoClientID).Scan(&uris); err != nil {
		return
	}
	for _, uri := range strings.Split(uris, ",") {
		if strings.TrimSpace(uri) == callback {
			return
		}
	}
	_, _ = database.WriteDB.Exec("UPDATE oidc_clients SET redirect_uris = ? WHERE client_id = ?",
		uris+","+callback, demoClientID)
}

func handleDemoPage(w http.ResponseWriter, r *http.Request) {
	callback := fmt.Sprintf("%s://%s/demo/callback", currentScheme(r), r.Host)
	registerDemoRedirectURI(callback)
	authorizeURL := "/" + demoIssuerSlug + "/authorize?client_id=" + demoClientID +
		"&redirect_uri=" + url.QueryEscape(callback) +
		"&response_type=code&scope=openid+profile+email"

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OneAuth 示例接入应用 (Demo App)</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: #060813;
            color: #94a3b8;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .demo-card {
            background: rgba(19, 26, 53, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(28px);
            border-radius: 28px;
            padding: 44px 38px;
            max-width: 520px;
            width: 100%;
            text-align: center;
            box-shadow: 0 30px 80px rgba(0,0,0,0.6);
        }
        .demo-badge {
            display: inline-block;
            background: rgba(0, 212, 255, 0.15);
            color: #00d4ff;
            border: 1px solid rgba(0, 212, 255, 0.3);
            font-size: 0.75rem;
            font-weight: 700;
            padding: 4px 12px;
            border-radius: 20px;
            margin-bottom: 20px;
            text-transform: uppercase;
        }
        h1 { font-size: 1.8rem; font-weight: 800; color: #f8fafc; margin-bottom: 12px; }
        p { font-size: 0.95rem; line-height: 1.6; margin-bottom: 28px; }
        .feature-box {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 28px;
            text-align: left;
            font-size: 0.88rem;
        }
        .feature-item { margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
        .feature-item:last-child { margin-bottom: 0; }
        .btn-login {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: 100%;
            padding: 15px 28px;
            border-radius: 14px;
            background: linear-gradient(135deg, #00d4ff 0%, #0066ff 100%);
            color: #000;
            text-decoration: none;
            font-size: 1.05rem;
            font-weight: 700;
            box-shadow: 0 10px 28px rgba(0, 212, 255, 0.35);
            transition: all 0.25s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 14px 34px rgba(0, 212, 255, 0.5);
            filter: brightness(1.08);
        }
        .admin-link {
            display: block;
            margin-top: 22px;
            color: #64748b;
            font-size: 0.85rem;
            text-decoration: none;
            transition: color 0.2s;
        }
        .admin-link:hover { color: #00d4ff; }
    </style>
</head>
<body>
    <div class="demo-card">
        <span class="demo-badge">Client Application Demo</span>
        <h1>接入方测试应用</h1>
        <p>这是一个已预配置信任的示例业务系统，点击下方按钮将跳转至 OneAuth 登录页展示 6 位群验证码。</p>
        
        <div class="feature-box">
            <div class="feature-item"><span>🛡️</span> <span>OAuth2 授权码流程 (Authorization Code)</span></div>
            <div class="feature-item"><span>⚡</span> <span>QQ 群发送验证码后，页面免刷新自动跳转</span></div>
            <div class="feature-item"><span>👤</span> <span>自动同步 QQ 号与 QQ 头像个人资料</span></div>
        </div>

        <a class="btn-login" href="{{.AuthorizeURL}}">
            <span>🚀 体验 QQ 群验证码登录</span>
        </a>

        <a class="admin-link" href="/admin">⚙️ 进入管理员控制台</a>
    </div>
</body>
</html>`
	// 占位符替换而非 fmt.Sprintf：页面 CSS 含大量 %%，替换法不会误伤。
	html = strings.Replace(html, "{{.AuthorizeURL}}", authorizeURL, 1)
	_, _ = w.Write([]byte(html))
}

func handleDemoCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "缺少 code 授权码", http.StatusBadRequest)
		return
	}

	// 后端向 /token 换取 Token
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("client_id", demoClientID)
	tokenForm.Set("client_secret", demoClientSecret)

	host := r.Host
	if host == "" {
		host = "localhost:9000"
	}
	tokenURL := fmt.Sprintf("%s://%s/%s/token", currentScheme(r), host, demoIssuerSlug)

	resp, err := callbackClient.PostForm(tokenURL, tokenForm)
	if err != nil {
		http.Error(w, "换取令牌失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tokenData map[string]interface{}
	_ = json.Unmarshal(body, &tokenData)

	idToken, _ := tokenData["id_token"].(string)

	// 换取失败必须如实展示：此前错误响应也会被渲染成“登录授权成功”，
	// 例如授权码被送到了另一个实例（demo 的 redirect_uri 与访问地址不一致
	// 时的典型症状），排查方向完全被误导。
	if idToken == "" {
		errCode, _ := tokenData["error"].(string)
		if errCode == "" {
			errCode = fmt.Sprintf("http_%d", resp.StatusCode)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>令牌换取失败 - 业务系统</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: #060813;
            color: #94a3b8;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .err-card {
            background: rgba(19, 26, 53, 0.65);
            border: 1px solid rgba(239, 68, 68, 0.35);
            backdrop-filter: blur(28px);
            border-radius: 28px;
            padding: 44px 38px;
            max-width: 560px;
            width: 100%%;
            text-align: center;
            box-shadow: 0 30px 80px rgba(0,0,0,0.6);
        }
        h1 { font-size: 1.6rem; font-weight: 800; color: #f8fafc; margin-bottom: 10px; }
        .err-badge {
            display: inline-block;
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            font-weight: 700;
            padding: 4px 16px;
            border-radius: 20px;
            margin-bottom: 22px;
        }
        p { font-size: 0.92rem; line-height: 1.7; margin-bottom: 10px; }
        .hint { color: #64748b; font-size: 0.84rem; }
        .btn-again {
            display: inline-block;
            margin-top: 20px;
            padding: 12px 26px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.08);
            color: #f8fafc;
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 600;
            transition: all 0.2s;
        }
        .btn-again:hover { background: rgba(255, 255, 255, 0.15); }
    </style>
</head>
<body>
    <div class="err-card">
        <h1>令牌换取失败</h1>
        <div class="err-badge">%s</div>
        <p>演示应用拿授权码回换 Token 时被 OneAuth 拒绝。</p>
        <p class="hint">常见原因：授权码已被消费或过期；回调地址与发起授权的站点不一致（如授权码被送达了另一个 OneAuth 实例）。</p>
        <a class="btn-again" href="/demo">🔄 重新发起测试</a>
    </div>
</body>
</html>`, template.HTMLEscapeString(errCode))
		_, _ = w.Write([]byte(html))
		return
	}

	// 解析 JWT payload 展示 QQ 信息
	var qqNumber string
	if parts := strings.Split(idToken, "."); len(parts) >= 2 {
		payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]interface{}
		_ = json.Unmarshal(payloadBytes, &claims)
		if sub, ok := claims["sub"].(string); ok {
			qqNumber = sub
		}
	}
	if qqNumber == "" {
		qqNumber = "100000001"
	}

	avatarURL := fmt.Sprintf("https://q1.qlogo.cn/g?b=qq&nk=%s&s=640", qqNumber)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>认证成功 - 业务系统</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: #060813;
            color: #94a3b8;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .result-card {
            background: rgba(19, 26, 53, 0.65);
            border: 1px solid rgba(16, 185, 129, 0.3);
            backdrop-filter: blur(28px);
            border-radius: 28px;
            padding: 44px 38px;
            max-width: 580px;
            width: 100%%;
            text-align: center;
            box-shadow: 0 30px 80px rgba(0,0,0,0.6);
        }
        .avatar {
            width: 90px;
            height: 90px;
            border-radius: 50%%;
            border: 3px solid #10b981;
            box-shadow: 0 0 25px rgba(16, 185, 129, 0.4);
            margin: 0 auto 16px;
            display: block;
        }
        h1 { font-size: 1.8rem; font-weight: 800; color: #f8fafc; margin-bottom: 6px; }
        .qq-badge {
            display: inline-block;
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95rem;
            font-weight: 700;
            padding: 4px 16px;
            border-radius: 20px;
            margin-bottom: 24px;
        }
        .raw-box {
            background: rgba(10, 14, 28, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 14px;
            padding: 14px;
            text-align: left;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            color: #cbd5e1;
            max-height: 140px;
            overflow-y: auto;
            word-break: break-all;
            margin-bottom: 24px;
        }
        .btn-again {
            display: inline-block;
            padding: 12px 26px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.08);
            color: #f8fafc;
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 600;
            transition: all 0.2s;
        }
        .btn-again:hover { background: rgba(255, 255, 255, 0.15); }
    </style>
</head>
<body>
    <div class="result-card">
        <img class="avatar" src="%s" alt="Avatar">
        <h1>登录授权成功！</h1>
        <div class="qq-badge">QQ: %s</div>
        <p style="font-size:0.9rem; margin-bottom:14px;">业务系统已成功通过 OIDC 协议换取到 RS256 JWT Token：</p>
        <div class="raw-box">%s</div>
        <a class="btn-again" href="/demo">🔄 重新发起测试</a>
    </div>
</body>
</html>`, avatarURL, qqNumber, template.HTMLEscapeString(string(body)))

	_, _ = w.Write([]byte(html))
}
