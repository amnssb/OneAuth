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
	"time"

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

func TestSessionStatusEndpoint(t *testing.T) {
	sess, err := session.DefaultManager.CreateSession("test_cli", "http://cb.local/cb", "st", "", "8888", 60)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// 1. Pending 状态
	req := httptest.NewRequest(http.MethodGet, "/api/session/status?session_id="+sess.SessionID, nil)
	rec := httptest.NewRecorder()
	handleSessionStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if res["status"] != "pending" {
		t.Fatalf("expected pending, got %v", res["status"])
	}

	// 2. Verified 状态
	if _, ok := session.DefaultManager.VerifyCode("qq", sess.VerifyCode, "10001", "8888"); !ok {
		t.Fatal("verify failed")
	}
	rec = httptest.NewRecorder()
	handleSessionStatus(rec, req)
	var res2 map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res2); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if res2["status"] != "verified" {
		t.Fatalf("expected verified, got %v", res2["status"])
	}
	if !strings.Contains(res2["redirect"].(string), sess.SessionID) {
		t.Fatalf("unexpected redirect: %v", res2["redirect"])
	}
}

// 统一根 Issuer 自动发现文档与 JWKS 测试
func TestRootIssuerDiscoveryAndJWKS(t *testing.T) {
	tmp := t.TempDir()
	if _, err := database.InitDB(filepath.Join(tmp, "root_disc.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer database.WriteDB.Close()
	defer database.DB.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "auth.example.com"
	rec := httptest.NewRecorder()
	handleRootDiscovery(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("root discovery status = %d body = %s", rec.Code, rec.Body.String())
	}

	var cfg map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if cfg["issuer"] != "http://auth.example.com" {
		t.Fatalf("root issuer must be root URL, got %v", cfg["issuer"])
	}
	if cfg["authorization_endpoint"] != "http://auth.example.com/authorize" {
		t.Fatalf("unexpected authorization_endpoint: %v", cfg["authorization_endpoint"])
	}
	if cfg["token_endpoint"] != "http://auth.example.com/token" {
		t.Fatalf("unexpected token_endpoint: %v", cfg["token_endpoint"])
	}
	if cfg["userinfo_endpoint"] != "http://auth.example.com/userinfo" {
		t.Fatalf("unexpected userinfo_endpoint: %v", cfg["userinfo_endpoint"])
	}
	if cfg["end_session_endpoint"] != "http://auth.example.com/logout" {
		t.Fatalf("unexpected end_session_endpoint: %v", cfg["end_session_endpoint"])
	}
	if cfg["revocation_endpoint"] != "http://auth.example.com/revoke" {
		t.Fatalf("unexpected revocation_endpoint: %v", cfg["revocation_endpoint"])
	}
	if cfg["introspection_endpoint"] != "http://auth.example.com/introspect" {
		t.Fatalf("unexpected introspection_endpoint: %v", cfg["introspection_endpoint"])
	}

	// 根 JWKS 端点
	reqJWKS := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	recJWKS := httptest.NewRecorder()
	handleRootJWKS(recJWKS, reqJWKS)
	if recJWKS.Code != http.StatusOK {
		t.Fatalf("root jwks status = %d", recJWKS.Code)
	}
	var jwks map[string]any
	if err := json.Unmarshal(recJWKS.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("root jwks must contain keys: %v", jwks)
	}
}

// 授权端点：nonce 传递与 RFC 6749 规范重定向测试
func TestAuthorizeNonceAndErrorRedirect(t *testing.T) {
	tmp := t.TempDir()
	if _, err := database.InitDB(filepath.Join(tmp, "auth_nonce.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer database.WriteDB.Close()
	defer database.DB.Close()

	setupTenantClient(t, "root_client", "secret123", "root-slug")

	// 1. 成功授权并携带 nonce
	req := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id=root_client&redirect_uri=http://cb.local/cb&response_type=code&scope=openid+profile&state=s1&nonce=n12345", nil)
	rec := httptest.NewRecorder()
	handleRootAuthorize(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize expected 302, got %d body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?session_id=") {
		t.Fatalf("unexpected redirect: %s", loc)
	}
	sessionID := strings.TrimPrefix(loc, "/login?session_id=")
	sess, ok := session.DefaultManager.GetSession(sessionID)
	if !ok {
		t.Fatalf("session not found: %s", sessionID)
	}
	if sess.Nonce != "n12345" {
		t.Fatalf("expected nonce n12345, got %q", sess.Nonce)
	}

	// 2. 错误 response_type 时重定向到 redirect_uri?error=...
	reqErr := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id=root_client&redirect_uri=http://cb.local/cb&response_type=token&scope=openid", nil)
	recErr := httptest.NewRecorder()
	handleRootAuthorize(recErr, reqErr)
	if recErr.Code != http.StatusFound {
		t.Fatalf("expected 302 error redirect, got %d", recErr.Code)
	}
	errLoc, _ := url.Parse(recErr.Header().Get("Location"))
	if errLoc.Query().Get("error") != "unsupported_response_type" {
		t.Fatalf("expected unsupported_response_type, got %v", errLoc.Query().Get("error"))
	}
}

// 令牌签发：at_hash 校验、独立 Access Token 与 Refresh Token 流转测试
func TestTokenIssuanceAtHashAndRefreshToken(t *testing.T) {
	tmp := t.TempDir()
	if _, err := database.InitDB(filepath.Join(tmp, "token_flow.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer database.WriteDB.Close()
	defer database.DB.Close()

	setupTenantClient(t, "flow_client", "secret_abc", "flow-app")

	sess, err := session.DefaultManager.CreateSessionWithOptions(session.CreateSessionOptions{
		ClientID:    "flow_client",
		RedirectURI: "http://cb.local/cb",
		State:       "state_xyz",
		Nonce:       "custom_nonce_888",
		Scopes:      []string{"openid", "profile", "email", "offline_access"},
		GroupID:     "8888",
		TTLSeconds:  60,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, ok := session.DefaultManager.VerifyCode("qq", sess.VerifyCode, "99999", "8888"); !ok {
		t.Fatal("verify code failed")
	}

	authCode, _, ok := session.DefaultManager.IssueAuthCode(sess.SessionID)
	if !ok {
		t.Fatal("issue auth code failed")
	}

	// 1. authorization_code 兑换令牌
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {"flow_client"},
		"client_secret": {"secret_abc"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRootToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleRootToken failed: %d %s", rec.Code, rec.Body.String())
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("decode token resp: %v", err)
	}

	if tokenResp.AccessToken == "" || tokenResp.IDToken == "" || tokenResp.RefreshToken == "" {
		t.Fatalf("missing tokens in response: %+v", tokenResp)
	}
	if tokenResp.AccessToken == tokenResp.IDToken {
		t.Fatal("access_token and id_token must be distinct tokens")
	}

	// 校验 ID Token Claims 中的 nonce 与 at_hash
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(tokenResp.IDToken, ".")[1])
	if err != nil {
		t.Fatalf("decode id token payload: %v", err)
	}
	var idClaims map[string]any
	if err := json.Unmarshal(payload, &idClaims); err != nil {
		t.Fatalf("unmarshal id claims: %v", err)
	}

	if idClaims["nonce"] != "custom_nonce_888" {
		t.Fatalf("expected nonce custom_nonce_888, got %v", idClaims["nonce"])
	}
	expectedAtHash := computeAtHash(tokenResp.AccessToken)
	if idClaims["at_hash"] != expectedAtHash {
		t.Fatalf("expected at_hash %s, got %v", expectedAtHash, idClaims["at_hash"])
	}

	// 2. 用 Refresh Token 换取新令牌
	rfForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenResp.RefreshToken},
		"client_id":     {"flow_client"},
		"client_secret": {"secret_abc"},
	}
	reqRF := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(rfForm.Encode()))
	reqRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recRF := httptest.NewRecorder()
	handleRootToken(recRF, reqRF)
	if recRF.Code != http.StatusOK {
		t.Fatalf("refresh token failed: %d %s", recRF.Code, recRF.Body.String())
	}

	var rfResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(recRF.Body.Bytes(), &rfResp); err != nil {
		t.Fatalf("decode rf resp: %v", err)
	}
	if rfResp.RefreshToken == "" || rfResp.RefreshToken == tokenResp.RefreshToken {
		t.Fatalf("refresh token should be rotated: old=%s, new=%s", tokenResp.RefreshToken, rfResp.RefreshToken)
	}

	// 3. 旧 Refresh Token 再次使用必须失败（已被轮换吊销）
	recReplay := httptest.NewRecorder()
	reqReplay := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(rfForm.Encode()))
	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleRootToken(recReplay, reqReplay)
	if recReplay.Code != http.StatusBadRequest {
		t.Fatalf("replayed refresh token must be rejected, got %d", recReplay.Code)
	}
}

// 令牌撤销 (RFC 7009) 与令牌内省 (RFC 7662) 测试
func TestRevokeAndIntrospect(t *testing.T) {
	tmp := t.TempDir()
	if _, err := database.InitDB(filepath.Join(tmp, "revoke_intro.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer database.WriteDB.Close()
	defer database.DB.Close()

	setupTenantClient(t, "ri_client", "ri_secret", "ri-app")

	now := time.Now()
	token := "sample_refresh_token_12345"
	if err := database.StoreRefreshToken(token, "ri_client", "55555", "qq", "openid profile", "", now.Add(time.Hour)); err != nil {
		t.Fatalf("store refresh token: %v", err)
	}

	// 1. 内省有效令牌
	introForm := url.Values{
		"token":         {token},
		"client_id":     {"ri_client"},
		"client_secret": {"ri_secret"},
	}
	reqIntro := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(introForm.Encode()))
	reqIntro.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recIntro := httptest.NewRecorder()
	handleRootIntrospect(recIntro, reqIntro)
	if recIntro.Code != http.StatusOK {
		t.Fatalf("introspect status = %d", recIntro.Code)
	}
	var introRes map[string]any
	if err := json.Unmarshal(recIntro.Body.Bytes(), &introRes); err != nil {
		t.Fatalf("decode introspect: %v", err)
	}
	if introRes["active"] != true || introRes["sub"] != "55555" {
		t.Fatalf("expected active=true sub=55555, got %+v", introRes)
	}

	// 2. 撤销令牌 (RFC 7009)
	revokeForm := url.Values{
		"token":         {token},
		"client_id":     {"ri_client"},
		"client_secret": {"ri_secret"},
	}
	reqRevoke := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(revokeForm.Encode()))
	reqRevoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recRevoke := httptest.NewRecorder()
	handleRootRevoke(recRevoke, reqRevoke)
	if recRevoke.Code != http.StatusOK {
		t.Fatalf("revoke status = %d", recRevoke.Code)
	}

	// 3. 再次内省该令牌，应为 active: false
	recIntro2 := httptest.NewRecorder()
	reqIntro2 := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(introForm.Encode()))
	reqIntro2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleRootIntrospect(recIntro2, reqIntro2)
	var introRes2 map[string]any
	_ = json.Unmarshal(recIntro2.Body.Bytes(), &introRes2)
	if introRes2["active"] != false {
		t.Fatalf("revoked token must be inactive, got %+v", introRes2)
	}
}

// RP-Initiated Logout 1.0 登出测试
func TestRPInitiatedLogout(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri=http://app.local/goodbye&state=xyz", nil)
	rec := httptest.NewRecorder()
	handleRootLogout(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "http://app.local/goodbye?state=xyz" {
		t.Fatalf("unexpected logout redirect: %s", loc)
	}
}

