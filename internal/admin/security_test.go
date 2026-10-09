package admin

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
