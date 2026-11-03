package admin

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"oneauth/internal/database"
)

// 限流取真实客户端 IP：只有直连方是可信反代时才采信转发头，
// 直连公网时伪造 CF-Connecting-IP / X-Forwarded-For 不能偷换限流桶。
func TestClientIPTrustedProxyOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", nil)
	req.RemoteAddr = "10.1.2.3:5678"
	req.Header.Set("CF-Connecting-IP", "198.51.100.55")
	req.Header.Set("X-Forwarded-For", "198.51.100.55")
	if got := clientIP(req); got != "198.51.100.55" {
		t.Fatalf("trusted proxy must yield forwarded client IP, got %q", got)
	}

	forged := httptest.NewRequest(http.MethodPost, "/api/admin/login", nil)
	forged.RemoteAddr = "203.0.113.9:5678"
	forged.Header.Set("CF-Connecting-IP", "1.2.3.4")
	if got := clientIP(forged); got != "203.0.113.9" {
		t.Fatalf("untrusted peer must keep RemoteAddr, got %q", got)
	}
}

// 账号维度限流：换 IP 爆破同一账号照样被锁，未被波及的账号不受牵连。
func TestLoginRateLimitPerAccount(t *testing.T) {
	if _, err := database.InitDB(filepath.Join(t.TempDir(), "admin_login.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() {
		database.WriteDB.Close()
		database.DB.Close()
		limiter.mu.Lock()
		limiter.entries = make(map[string]*loginFails)
		limiter.mu.Unlock()
	})

	login := func(remoteAddr, user string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/login",
			strings.NewReader(`{"username":"`+user+`","password":"wrong-pass"}`))
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		handleAdminLogin(rec, req)
		return rec.Code
	}

	for i := 0; i < 5; i++ {
		if code := login("203.0.113.5:1000", "victim"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: expected 401, got %d", i+1, code)
		}
	}
	// 同账号换 IP：账号维度已锁 → 429
	if code := login("198.51.100.7:1000", "victim"); code != http.StatusTooManyRequests {
		t.Fatalf("same account from another IP must be locked, got %d", code)
	}
	// 另一账号、另一 IP：不受牵连 → 401 而非 429
	if code := login("198.51.100.8:1000", "bystander"); code != http.StatusUnauthorized {
		t.Fatalf("unrelated account must not be locked, got %d", code)
	}
}

func multipartBinary(t *testing.T, checksum string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("binary", "oneauth")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write([]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if checksum != "" {
		if err := mw.WriteField("checksum", checksum); err != nil {
			t.Fatalf("write checksum: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

// 登出跳转白名单必须能经管理 API 完整读写，且非法值在入口就被拒。
func TestClientPostLogoutURIRoundTrip(t *testing.T) {
	if _, err := database.InitDB(filepath.Join(t.TempDir(), "admin_postlogout.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() { database.WriteDB.Close(); database.DB.Close() })

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/clients", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handleCreateClient(rec, req)
		return rec
	}

	rec := post(`{"client_name":"A","redirect_uris":"https://a.com/cb",
		"post_logout_redirect_uris":"https://a.com/logged_out","issuer_slug":"pl-rt"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create must 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	list := func() []ClientInfo {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/clients", nil)
		w := httptest.NewRecorder()
		handleListClients(w, req)
		var out []ClientInfo
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		return out
	}
	found := false
	for _, c := range list() {
		if c.ClientID == created.ClientID {
			found = true
			if c.PostLogoutURIs != "https://a.com/logged_out" {
				t.Fatalf("whitelist not persisted, got %q", c.PostLogoutURIs)
			}
		}
	}
	if !found {
		t.Fatal("created client missing from list")
	}

	// 编辑：清空白名单（退回同源/相对路径策略）
	put := httptest.NewRequest(http.MethodPut, "/api/admin/clients/"+created.ClientID,
		strings.NewReader(`{"client_name":"A","redirect_uris":"https://a.com/cb","post_logout_redirect_uris":""}`))
	put.SetPathValue("id", created.ClientID)
	putRec := httptest.NewRecorder()
	handleUpdateClient(putRec, put)
	if putRec.Code != http.StatusOK {
		t.Fatalf("update must 200, got %d: %s", putRec.Code, putRec.Body.String())
	}
	for _, c := range list() {
		if c.ClientID == created.ClientID && c.PostLogoutURIs != "" {
			t.Fatalf("whitelist must be clearable, got %q", c.PostLogoutURIs)
		}
	}

	// 非 http(s) 地址直接 400
	bad := post(`{"client_name":"B","redirect_uris":"https://b.com/cb",
		"post_logout_redirect_uris":"javascript:alert(1)","issuer_slug":"pl-bad"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("non-http post-logout URI must 400, got %d: %s", bad.Code, bad.Body.String())
	}
}

// 发布包校验值必填：checksum 可选时任意管理会话都能上传任意二进制覆盖主程序。
func TestApplyUpdateRequiresChecksum(t *testing.T) {
	body, ctype := multipartBinary(t, "")
	req := httptest.NewRequest(http.MethodPost, "/api/admin/update/apply", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	handleApplyUpdate(rec, req)

	if rec.Code == http.StatusInternalServerError && strings.Contains(rec.Body.String(), "创建临时更新文件失败") {
		t.Skip("temp dir not writable in this environment")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing checksum must be rejected with 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "SHA-256") {
		t.Fatalf("expected checksum error, got %s", rec.Body.String())
	}
}

// tryReserve 必须原子预占：第 max 次预占即锁定，之后的并发预占
// 一律失败——这是 TOCTOU 修复的核心，bcrypt 之前就要计入名额。
func TestTryReserveIsAtomic(t *testing.T) {
	l := newTestLimiter(60*1000, 3, 60*1000)
	if !l.tryReserve("k") || !l.tryReserve("k") || !l.tryReserve("k") {
		t.Fatal("first max reservations must succeed")
	}
	if l.tryReserve("k") {
		t.Fatal("reservation past the threshold must fail")
	}
	if l.blocked("k") == 0 {
		t.Fatal("threshold must lock the key")
	}
}

// 并发登录不能绕过限流：64 条并发错误口令里最多 max 条拿到 401，
// 其余必须 429。旧实现先 blocked() 检查、bcrypt 后才记失败，
// 256 并发能拿到 256 个 401（实测 ~51x）。
func TestLoginRateLimitConcurrentTOCTOU(t *testing.T) {
	if _, err := database.InitDB(filepath.Join(t.TempDir(), "toctou.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() {
		database.WriteDB.Close()
		database.DB.Close()
		limiter.mu.Lock()
		limiter.entries = make(map[string]*loginFails)
		limiter.mu.Unlock()
	})

	const n = 64
	var unauthorized, tooMany atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/admin/login",
				strings.NewReader(`{"username":"toctou-victim","password":"wrong-pass"}`))
			req.RemoteAddr = "203.0.113.60:1000"
			rec := httptest.NewRecorder()
			handleAdminLogin(rec, req)
			switch rec.Code {
			case http.StatusUnauthorized:
				unauthorized.Add(1)
			case http.StatusTooManyRequests:
				tooMany.Add(1)
			default:
				t.Errorf("unexpected login status %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	if got := unauthorized.Load(); got > 5 {
		t.Fatalf("concurrent failures must be capped at 5 attempts, got %d x 401 of %d", got, n)
	}
	if got := tooMany.Load(); got == 0 {
		t.Fatalf("excess concurrent attempts must be rate-limited, got 0 x 429 of %d", n)
	}
}

// 反代后面拿不到转发头时，127.0.0.1 不能当成可区分的限流桶：
// 所有访客共享它，5 次失败会把全体管理员锁定 15 分钟。
func TestClientIPInfoSharedLoopbackBucket(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", nil)
	req.RemoteAddr = "127.0.0.1:9000"
	if _, identifiable := clientIPInfo(req); identifiable {
		t.Fatal("loopback RemoteAddr without forwarding headers must not be identifiable")
	}
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	ip, identifiable := clientIPInfo(req)
	if !identifiable || ip != "198.51.100.9" {
		t.Fatalf("forwarded IP behind loopback proxy must be identifiable, got %q identifiable=%v", ip, identifiable)
	}
}

// OneBot Token 设置项：空值、历史公开默认值、过短口令一律拒绝。
func TestOnebotTokenSettingRejectsWeakValues(t *testing.T) {
	for _, v := range []string{"", "  ", "oneauth_secure_secret_token", "short"} {
		if err := validateSetting("onebot_token", v); err == nil {
			t.Fatalf("onebot_token %q must be rejected", v)
		}
	}
	if err := validateSetting("onebot_token", strings.Repeat("x", 32)); err != nil {
		t.Fatalf("strong token must be accepted: %v", err)
	}
}

// 管理会话 Cookie：登录必须下发 HttpOnly Cookie，仅凭 Cookie
// （不带 Bearer）就能访问管理接口；跨站 Origin 的 Cookie 请求被拒。
func TestAdminSessionCookieAuth(t *testing.T) {
	if _, err := database.InitDB(filepath.Join(t.TempDir(), "cookie.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() {
		database.WriteDB.Close()
		database.DB.Close()
		limiter.mu.Lock()
		limiter.entries = make(map[string]*loginFails)
		limiter.mu.Unlock()
		adminStore.mu.Lock()
		adminStore.sessions = make(map[string]*adminClaims)
		adminStore.mu.Unlock()
	})

	// 创建管理员：先走初始化接口。
	setupReq := httptest.NewRequest(http.MethodPost, "/api/admin/setup",
		strings.NewReader(`{"username":"cookie-admin","password":"correct-horse-1"}`))
	setupReq.RemoteAddr = "203.0.113.70:1000"
	setupRec := httptest.NewRecorder()
	handleInitialSetup(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup must succeed, got %d: %s", setupRec.Code, setupRec.Body.String())
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/api/admin/login",
		strings.NewReader(`{"username":"cookie-admin","password":"correct-horse-1"}`))
	loginReq.RemoteAddr = "203.0.113.70:1000"
	loginRec := httptest.NewRecorder()
	handleAdminLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login must succeed, got %d: %s", loginRec.Code, loginRec.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == adminSessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login must set the admin session cookie")
	}
	if !cookie.HttpOnly {
		t.Fatal("admin session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("admin session cookie must be SameSite=Lax, got %v", cookie.SameSite)
	}

	statsWithCookie := func(origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil)
		req.AddCookie(cookie)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		authMiddleware(handleStats)(rec, req)
		return rec
	}
	if rec := statsWithCookie(""); rec.Code != http.StatusOK {
		t.Fatalf("cookie-only auth must succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := statsWithCookie("https://evil.example"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-site Origin with cookie must be rejected, got %d", rec.Code)
	}
}

// 校验值不匹配同样在替换主程序之前拒绝。
func TestApplyUpdateRejectsMismatchedChecksum(t *testing.T) {
	body, ctype := multipartBinary(t, strings.Repeat("0", 64))
	req := httptest.NewRequest(http.MethodPost, "/api/admin/update/apply", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	handleApplyUpdate(rec, req)

	if rec.Code == http.StatusInternalServerError && strings.Contains(rec.Body.String(), "创建临时更新文件失败") {
		t.Skip("temp dir not writable in this environment")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched checksum must be rejected with 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "校验失败") {
		t.Fatalf("expected checksum mismatch error, got %s", rec.Body.String())
	}
}
