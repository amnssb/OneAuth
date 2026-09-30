package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"oneauth/internal/database"
	"oneauth/internal/session"
)

// 端到端回归：QQ 身份核销后 /token 签发的 JWT 必须保持既有 sub 语义
// （即 QQ 号），并新增 identity_provider 声明 —— 已接入的第三方
// （Gitea/Nextcloud/Grafana）依赖这些字段，重构时不能变。
func TestTokenIssuanceQQIdentity(t *testing.T) {
	tmp := t.TempDir()
	if _, err := database.InitDB(filepath.Join(tmp, "t.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer database.WriteDB.Close()
	defer database.DB.Close()
	InitKeys(filepath.Join(tmp, "key.pem"))

	hash := sha256.Sum256([]byte("t_secret"))
	database.WriteDB.Exec(
		"INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug) VALUES (?, ?, ?, ?, ?)",
		"t_client", base64.RawURLEncoding.EncodeToString(hash[:]), "t", "http://cb.local/cb", "t-tenant")

	sess, err := session.DefaultManager.CreateSession("t_client", "http://cb.local/cb", "st", "", "777777", 60)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, ok := session.DefaultManager.VerifyCode("qq", sess.VerifyCode, "10001", "777777"); !ok {
		t.Fatal("verify code failed")
	}
	authCode, _, ok := session.DefaultManager.IssueAuthCode(sess.SessionID)
	if !ok {
		t.Fatal("issue auth code failed")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {"t_client"},
		"client_secret": {"t_secret"},
	}
	// 租户级 /token 端点：路径通配段 slug 通过 SetPathValue 注入。
	req := httptest.NewRequest(http.MethodPost, "/t-tenant/token", strings.NewReader(form.Encode()))
	req.SetPathValue("slug", "t-tenant")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/token status = %d body=%s", rec.Code, rec.Body.String())
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(tokenResp.IDToken, ".")[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if claims["sub"] != "10001" {
		t.Fatalf("sub must stay the QQ number, got %v", claims["sub"])
	}
	if claims["identity_provider"] != "qq" {
		t.Fatalf("missing identity_provider claim, got %v", claims["identity_provider"])
	}
	if claims["email"] != "10001@qq.com" || claims["picture"] == nil || claims["name"] != "QQ用户_10001" {
		t.Fatalf("unexpected qq claims: %v", claims)
	}

	// 授权码一次性：同一 code 复用必须被拒。
	rec2 := httptest.NewRecorder()
	replay := httptest.NewRequest(http.MethodPost, "/t-tenant/token", strings.NewReader(form.Encode()))
	replay.SetPathValue("slug", "t-tenant")
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleToken(rec2, replay)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("replayed code must be rejected, got %d", rec2.Code)
	}
}

func setupTenantClient(t *testing.T, clientID, secret, slug string) {
	t.Helper()
	hash := sha256.Sum256([]byte(secret))
	if _, err := database.WriteDB.Exec(
		"INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug) VALUES (?, ?, ?, ?, ?)",
		clientID, base64.RawURLEncoding.EncodeToString(hash[:]), clientID, "http://cb.local/cb", slug,
	); err != nil {
		t.Fatalf("insert client %s: %v", clientID, err)
	}
}

// mintToken 走完整核销流程，返回某租户签发的 id_token。
func mintToken(t *testing.T, clientID, secret, slug string) string {
	t.Helper()
	sess, err := session.DefaultManager.CreateSession(clientID, "http://cb.local/cb", "st", "", "777777", 60)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, ok := session.DefaultManager.VerifyCode("qq", sess.VerifyCode, "20002", "777777"); !ok {
		t.Fatal("verify code failed")
	}
	authCode, _, ok := session.DefaultManager.IssueAuthCode(sess.SessionID)
	if !ok {
		t.Fatal("issue auth code failed")
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {authCode},
		"client_id": {clientID}, "client_secret": {secret},
	}
	req := httptest.NewRequest(http.MethodPost, "/"+slug+"/token", strings.NewReader(form.Encode()))
	req.SetPathValue("slug", slug)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint token for %s failed: %d %s", slug, rec.Code, rec.Body.String())
	}
	var resp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	return resp.IDToken
}

// 发现文档必须携带带 slug 前缀的租户 Issuer 与各端点。
func TestTenantDiscovery(t *testing.T) {
	tmp := t.TempDir()
	if _, err := database.InitDB(filepath.Join(tmp, "d.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer database.WriteDB.Close()
	defer database.DB.Close()
	setupTenantClient(t, "c_disc", "s", "acme")

	req := httptest.NewRequest(http.MethodGet, "/acme/.well-known/openid-configuration", nil)
	req.SetPathValue("slug", "acme")
	req.Host = "auth.example.com"
	rec := httptest.NewRecorder()
	handleDiscovery(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status = %d", rec.Code)
	}
	var cfg map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if cfg["issuer"] != "http://auth.example.com/acme" {
		t.Fatalf("issuer must carry slug, got %v", cfg["issuer"])
	}
	if cfg["authorization_endpoint"] != "http://auth.example.com/acme/authorize" {
		t.Fatalf("unexpected authorization_endpoint: %v", cfg["authorization_endpoint"])
	}

	// 未知 slug -> 404
	miss := httptest.NewRequest(http.MethodGet, "/nope/.well-known/openid-configuration", nil)
	miss.SetPathValue("slug", "nope")
	missRec := httptest.NewRecorder()
	handleDiscovery(missRec, miss)
	if missRec.Code != http.StatusNotFound {
		t.Fatalf("unknown slug must 404, got %d", missRec.Code)
	}
}

// 跨租户令牌隔离：A 租户签发的 id_token 拿到 B 租户 userinfo 必须被拒，
// 拿回 A 租户 userinfo 则成功。
func TestUserinfoTenantIsolation(t *testing.T) {
	tmp := t.TempDir()
	if _, err := database.InitDB(filepath.Join(tmp, "iso.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer database.WriteDB.Close()
	defer database.DB.Close()

	setupTenantClient(t, "c_a", "sa", "tenant-a")
	setupTenantClient(t, "c_b", "sb", "tenant-b")

	tokenA := mintToken(t, "c_a", "sa", "tenant-a")

	callUserinfo := func(slug, token string) int {
		req := httptest.NewRequest(http.MethodGet, "/"+slug+"/userinfo", nil)
		req.SetPathValue("slug", slug)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handleUserinfo(rec, req)
		return rec.Code
	}

	if code := callUserinfo("tenant-a", tokenA); code != http.StatusOK {
		t.Fatalf("token A at tenant A must succeed, got %d", code)
	}
	if code := callUserinfo("tenant-b", tokenA); code != http.StatusUnauthorized {
		t.Fatalf("token A at tenant B must be rejected, got %d", code)
	}
}

// 按应用绑定验证群回归：authorize 建会话时，应用级 target_group_id 优先，
// 未设置的应用回落全局 target_group_id。
func TestAuthorizeResolvesClientGroup(t *testing.T) {
	tmp := t.TempDir()
	if _, err := database.InitDB(filepath.Join(tmp, "grp.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer database.WriteDB.Close()
	defer database.DB.Close()

	if err := database.SetSetting("target_group_id", "10000"); err != nil {
		t.Fatalf("set global group: %v", err)
	}

	hash := sha256.Sum256([]byte("s1"))
	secretHash := base64.RawURLEncoding.EncodeToString(hash[:])
	if _, err := database.WriteDB.Exec(
		"INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug, target_group_id) VALUES (?, ?, 'g', 'http://cb.local/cb', 'grp-tenant', '20000')",
		"grp_client", secretHash,
	); err != nil {
		t.Fatalf("insert client with own group: %v", err)
	}
	if _, err := database.WriteDB.Exec(
		"INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug) VALUES (?, ?, 'i', 'http://cb.local/cb', 'inherit-tenant')",
		"inherit_client", secretHash,
	); err != nil {
		t.Fatalf("insert client without group: %v", err)
	}

	groupOf := func(slug, clientID string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet,
			"/"+slug+"/authorize?client_id="+clientID+"&redirect_uri=http://cb.local/cb&response_type=code&scope=openid", nil)
		req.SetPathValue("slug", slug)
		rec := httptest.NewRecorder()
		handleAuthorize(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("authorize %s status = %d body=%s", clientID, rec.Code, rec.Body.String())
		}
		sess, ok := session.DefaultManager.GetSession(strings.TrimPrefix(rec.Header().Get("Location"), "/login?session_id="))
		if !ok {
			t.Fatalf("session for %s not found", clientID)
		}
		return sess.GroupID
	}

	if g := groupOf("grp-tenant", "grp_client"); g != "20000" {
		t.Fatalf("per-client group must win, got %q", g)
	}
	if g := groupOf("inherit-tenant", "inherit_client"); g != "10000" {
		t.Fatalf("empty per-client group must fall back to global, got %q", g)
	}
}
