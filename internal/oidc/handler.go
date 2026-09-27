package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwtLib "github.com/golang-jwt/jwt/v5"

	"oneauth/internal/database"
	"oneauth/internal/identity"
	"oneauth/internal/session"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
)

// InitKeys initializes RSA keys for signing JWTs.
func InitKeys(keyPath string) {
	data, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				privateKey = parsedKey
				publicKey = &privateKey.PublicKey
				kid = computeKID(publicKey)
				log.Printf("[OIDC] 密钥对已从文件加载 (kid: %s)", kid)
				return
			}
		}
	}

	log.Printf("[OIDC] 正在生成新的 RSA-2048 密钥对...")
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("[OIDC] RSA 密钥生成失败: %v", err)
	}
	publicKey = &privateKey.PublicKey
	kid = computeKID(publicKey)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		log.Fatalf("[OIDC] 密钥文件写入失败: %v", err)
	}
	log.Printf("[OIDC] RSA-2048 密钥对已生成并持久化 (kid: %s)", kid)
}

func computeKID(pub *rsa.PublicKey) string {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("[OIDC] 公钥序列化失败: %v", err)
	}
	hash := sha256.Sum256(derBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:8])
}

// RegisterRoutes registers all OIDC endpoints.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", handleJWKS)
	mux.HandleFunc("GET /authorize", handleAuthorize)
	mux.HandleFunc("POST /token", handleToken)
	mux.HandleFunc("GET /userinfo", handleUserinfo)
	mux.HandleFunc("GET /api/session/stream", handleSSE)
	mux.HandleFunc("GET /api/session/callback", handleSessionCallback)
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := getIssuer(r)
	config := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nonce",
			"name", "preferred_username", "email", "email_verified", "picture",
		},
	}
	writeJSON(w, http.StatusOK, config)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	if publicKey == nil {
		http.Error(w, "Keys not initialized", http.StatusInternalServerError)
		return
	}

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			},
		},
	}
	writeJSON(w, http.StatusOK, jwks)
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")

	if responseType != "code" {
		http.Error(w, "unsupported_response_type: 仅支持 authorization_code 流程", http.StatusBadRequest)
		return
	}
	if clientID == "" || redirectURI == "" {
		http.Error(w, "invalid_request: 缺少必需参数 client_id 或 redirect_uri", http.StatusBadRequest)
		return
	}
	if !strings.Contains(scope, "openid") {
		http.Error(w, "invalid_scope: scope 必须包含 openid", http.StatusBadRequest)
		return
	}

	if !validateClient(clientID, redirectURI) {
		http.Error(w, "unauthorized_client: 未注册的 client_id 或 redirect_uri 不合法", http.StatusForbidden)
		return
	}

	ttlStr := database.GetSetting("code_ttl", "180")
	ttl, _ := strconv.Atoi(ttlStr)
	if ttl <= 0 {
		ttl = 180
	}

	sess, err := session.DefaultManager.CreateSession(clientID, redirectURI, state, codeChallenge, ttl)
	if err != nil {
		http.Error(w, "server_error: 会话创建失败", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login?session_id="+sess.SessionID, http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	codeVerifier := r.FormValue("code_verifier")

	if grantType != "authorization_code" || code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	// 支持 Basic Auth
	if clientID == "" {
		if bID, bSec, ok := r.BasicAuth(); ok {
			clientID = bID
			clientSecret = bSec
		}
	}

	sess, ok := session.DefaultManager.ExchangeCode(code)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	if sess.ClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}

	// PKCE 校验
	if sess.CodeChallenge != "" {
		if codeVerifier == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_grant",
				"error_description": "code_verifier required for PKCE",
			})
			return
		}
		h := sha256.Sum256([]byte(codeVerifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
		if computedChallenge != sess.CodeChallenge {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_grant",
				"error_description": "PKCE verification failed",
			})
			return
		}
	} else {
		// 无 PKCE 时验证 client_secret
		if !validateClientSecret(clientID, clientSecret) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
	}

	issuer := getIssuer(r)
	now := time.Now()

	profile := identity.ProfileFor(identity.Identity{Provider: sess.Provider, UserID: sess.UserID})

	claims := jwtLib.MapClaims{
		"iss": issuer,
		"sub": sess.UserID,
		"aud": clientID,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		// 平台相关资料由 identity.ProfileFor 按来源平台生成；
		// identity_provider 供接入方区分登录平台（新增声明，向后兼容）。
		"identity_provider": sess.Provider,
	}
	for k, v := range profile.Claims() {
		claims[k] = v
	}

	token := jwtLib.NewWithClaims(jwtLib.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	idTokenStr, err := token.SignedString(privateKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	resp := map[string]interface{}{
		"access_token": idTokenStr,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idTokenStr,
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleUserinfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwtLib.Parse(tokenStr, func(t *jwtLib.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtLib.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil || !token.Valid {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwtLib.MapClaims)
	if !ok {
		http.Error(w, "Invalid Claims", http.StatusUnauthorized)
		return
	}

	sub, _ := claims["sub"].(string)
	provider, _ := claims["identity_provider"].(string)
	userInfo := identity.ProfileFor(identity.Identity{Provider: provider, UserID: sub}).Claims()
	userInfo["sub"] = sub
	userInfo["identity_provider"] = provider
	writeJSON(w, http.StatusOK, userInfo)
}

func handleSSE(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	sess, exists := session.DefaultManager.GetSession(sessionID)
	if !exists {
		http.Error(w, "会话不存在", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "不支持流式响应", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	// 周期性 keepalive 注释行，防止空闲 SSE 长连接被代理/负载均衡掐断；
	// 大量并发登录页各挂一条 SSE 时尤其重要。
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	deadline := time.NewTimer(time.Until(sess.ExpiresAt))
	defer deadline.Stop()

	for {
		select {
		case <-sess.NotifyChan:
			fmt.Fprintf(w, "data: {\"status\":\"verified\",\"redirect\":\"/api/session/callback?session_id=%s\"}\n\n", sessionID)
			flusher.Flush()
			return
		case <-r.Context().Done():
			return
		case <-deadline.C:
			fmt.Fprintf(w, "data: {\"status\":\"expired\"}\n\n")
			flusher.Flush()
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func handleSessionCallback(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	authCode, sess, ok := session.DefaultManager.IssueAuthCode(sessionID)
	if !ok {
		http.Error(w, "会话状态无效", http.StatusBadRequest)
		return
	}

	redirectURL := sess.RedirectURI + "?code=" + authCode
	if sess.State != "" {
		redirectURL += "&state=" + sess.State
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func validateClient(clientID, redirectURI string) bool {
	var storedURIs string
	err := database.DB.QueryRow(
		"SELECT redirect_uris FROM oidc_clients WHERE client_id = ?", clientID,
	).Scan(&storedURIs)
	if err != nil {
		return false
	}
	for _, uri := range strings.Split(storedURIs, ",") {
		if strings.TrimSpace(uri) == redirectURI {
			return true
		}
	}
	return false
}

func validateClientSecret(clientID, secret string) bool {
	var storedHash string
	err := database.DB.QueryRow(
		"SELECT client_secret_hash FROM oidc_clients WHERE client_id = ?", clientID,
	).Scan(&storedHash)
	if err != nil {
		return false
	}
	return checkPasswordHash(secret, storedHash)
}

func getIssuer(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[OIDC] JSON 响应写入失败: %v", err)
	}
}

func checkPasswordHash(password, hash string) bool {
	h := sha256.Sum256([]byte(password))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}
