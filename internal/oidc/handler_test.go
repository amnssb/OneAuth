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
		"INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris) VALUES (?, ?, ?, ?)",
		"t_client", base64.RawURLEncoding.EncodeToString(hash[:]), "t", "http://cb.local/cb")

	sess, err := session.DefaultManager.CreateSession("t_client", "http://cb.local/cb", "st", "", 60)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, ok := session.DefaultManager.VerifyCode("qq", sess.VerifyCode, "10001"); !ok {
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
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
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
	handleToken(rec2, httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode())))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("replayed code must be rejected, got %d", rec2.Code)
	}
}
