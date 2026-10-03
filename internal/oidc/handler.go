package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jwtLib "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"oneauth/internal/database"
	"oneauth/internal/identity"
	"oneauth/internal/session"
)

// InitKeys 保留为兼容旧调用入口的空操作：签名密钥由 SQLite 惰性加载/生成，
// 统一根 Issuer 与各租户 Issuer 分别拥有持久化 RSA-2048 密钥对。
func InitKeys(keyPath string) {
	log.Printf("[OIDC] 签名密钥由 SQLite 自动化管理，已支持统一根 Issuer 与多租户双模运作")
}

func computeKID(pub *rsa.PublicKey) string {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("[OIDC] 公钥序列化失败: %v", err)
	}
	hash := sha256.Sum256(derBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:8])
}

// computeAtHash 按照 OIDC Core 1.0 Section 3.1.3.6 规范计算 access_token 的 at_hash。
// RS256 算法下使用 SHA-256 哈希取前 128 位并做 Base64URL 编码。
func computeAtHash(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	half := h[:len(h)/2]
	return base64.RawURLEncoding.EncodeToString(half)
}

func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// corsMetadata 允许任意来源跨域读取公开的发现文档与 JWKS。
func corsMetadata(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// tenantMux 承载所有 /{slug}/... 追加式租户端点。
var tenantMux = func() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /{slug}/.well-known/openid-configuration", corsMetadata(handleTenantDiscovery))
	m.HandleFunc("OPTIONS /{slug}/.well-known/openid-configuration", corsMetadata(handleTenantDiscovery))
	m.HandleFunc("GET /{slug}/.well-known/jwks.json", corsMetadata(handleTenantJWKS))
	m.HandleFunc("OPTIONS /{slug}/.well-known/jwks.json", corsMetadata(handleTenantJWKS))
	m.HandleFunc("GET /{slug}/authorize", handleTenantAuthorize)
	m.HandleFunc("POST /{slug}/token", handleTenantToken)
	m.HandleFunc("GET /{slug}/userinfo", handleTenantUserinfo)
	m.HandleFunc("POST /{slug}/userinfo", handleTenantUserinfo)
	m.HandleFunc("POST /{slug}/revoke", handleTenantRevoke)
	m.HandleFunc("POST /{slug}/introspect", handleTenantIntrospect)
	m.HandleFunc("GET /{slug}/logout", handleTenantLogout)
	m.HandleFunc("POST /{slug}/logout", handleTenantLogout)
	return m
}()

// reservedFirstSegments 是主 mux 上已注册的固定首段：Wrap 遇到这些首段的
// 请求一律交主 mux 处理，其余（视为 issuer_slug）交 tenantMux。
var reservedFirstSegments = map[string]bool{
	"":            true, // 根路径 "/"
	"static":      true,
	"login":       true,
	"admin":       true,
	"demo":        true,
	"api":         true,
	"ws":          true,
	".well-known": true,
	"favicon.ico": true,
	"authorize":   true,
	"token":       true,
	"userinfo":    true,
	"revoke":      true,
	"introspect":  true,
	"logout":      true,
}

// RegisterRoutes 在主 mux 上注册统一根 Issuer 端点以及 RFC 8414 插入式端点。
func RegisterRoutes(mux *http.ServeMux) {
	// 统一根 Issuer OIDC 协议端点
	mux.HandleFunc("GET /.well-known/openid-configuration", corsMetadata(handleRootDiscovery))
	mux.HandleFunc("OPTIONS /.well-known/openid-configuration", corsMetadata(handleRootDiscovery))
	mux.HandleFunc("GET /.well-known/jwks.json", corsMetadata(handleRootJWKS))
	mux.HandleFunc("OPTIONS /.well-known/jwks.json", corsMetadata(handleRootJWKS))

	mux.HandleFunc("GET /authorize", handleRootAuthorize)
	mux.HandleFunc("POST /token", handleRootToken)
	mux.HandleFunc("GET /userinfo", handleRootUserinfo)
	mux.HandleFunc("POST /userinfo", handleRootUserinfo)
	mux.HandleFunc("POST /revoke", handleRootRevoke)
	mux.HandleFunc("POST /introspect", handleRootIntrospect)
	mux.HandleFunc("GET /logout", handleRootLogout)
	mux.HandleFunc("POST /logout", handleRootLogout)

	// RFC 8414 插入式发现路径（多 Issuer 兼容）
	mux.HandleFunc("GET /.well-known/openid-configuration/{slug}", corsMetadata(handleDiscoveryRFC8414))
	mux.HandleFunc("GET /.well-known/jwks.json/{slug}", corsMetadata(handleJWKSRFC8414))

	// 会话相关端点（与 issuer 无关，登录页/SSE 共用）
	mux.HandleFunc("GET /api/session/stream", handleSSE)
	mux.HandleFunc("GET /api/session/status", handleSessionStatus)
	mux.HandleFunc("GET /api/session/callback", handleSessionCallback)
}

// Wrap 把主 mux 包成最终 http.Handler：请求首段命中固定路由 → 主 mux；
// 否则视为 issuer_slug → tenantMux。
func Wrap(main http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first := firstSegment(r.URL.Path)
		if reservedFirstSegments[first] {
			main.ServeHTTP(w, r)
			return
		}
		tenantMux.ServeHTTP(w, r)
	})
}

func firstSegment(path string) string {
	path = strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return path
}

func resolveTenant(w http.ResponseWriter, r *http.Request) (slug, clientID string, ok bool) {
	slug = r.PathValue("slug")
	if slug == "" {
		http.NotFound(w, r)
		return "", "", false
	}
	clientID, found := database.ClientIDForSlug(slug)
	if !found {
		http.NotFound(w, r)
		return "", "", false
	}
	return slug, clientID, true
}

func buildIssuer(r *http.Request, slug string) string {
	baseURL := getBaseURL(r)
	if slug == "" {
		return baseURL
	}
	return baseURL + "/" + slug
}

// tenantIssuer 保留向后兼容
func tenantIssuer(r *http.Request, slug string) string {
	return buildIssuer(r, slug)
}

// redirectAuthorizeError 按照 RFC 6749 Section 4.1.2.1 规范把授权错误重定向到 redirect_uri
func redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, errCode+": "+errDesc, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func buildDiscoveryConfig(r *http.Request, slug string) map[string]interface{} {
	issuer := buildIssuer(r, slug)
	authEndpoint := issuer + "/authorize"
	tokenEndpoint := issuer + "/token"
	userinfoEndpoint := issuer + "/userinfo"
	jwksURI := issuer + "/.well-known/jwks.json"
	logoutEndpoint := issuer + "/logout"
	revokeEndpoint := issuer + "/revoke"
	introspectEndpoint := issuer + "/introspect"

	return map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                authEndpoint,
		"token_endpoint":                        tokenEndpoint,
		"userinfo_endpoint":                     userinfoEndpoint,
		"jwks_uri":                              jwksURI,
		"end_session_endpoint":                  logoutEndpoint,
		"revocation_endpoint":                   revokeEndpoint,
		"introspection_endpoint":                introspectEndpoint,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
			"name", "preferred_username", "email", "email_verified", "picture", "identity_provider",
		},
	}
}

func handleDiscoveryCore(w http.ResponseWriter, r *http.Request, slug string) {
	writeJSON(w, http.StatusOK, buildDiscoveryConfig(r, slug))
}

func handleRootDiscovery(w http.ResponseWriter, r *http.Request) {
	handleDiscoveryCore(w, r, "")
}

func handleTenantDiscovery(w http.ResponseWriter, r *http.Request) {
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	handleDiscoveryCore(w, r, slug)
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		handleRootDiscovery(w, r)
		return
	}
	handleTenantDiscovery(w, r)
}

func handleDiscoveryRFC8414(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	if _, found := database.ClientIDForSlug(slug); !found {
		http.NotFound(w, r)
		return
	}
	handleDiscoveryCore(w, r, slug)
}

func handleJWKSCore(w http.ResponseWriter, r *http.Request, slug string) {
	entries, err := tenantJWKSEntries(slug)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if len(entries) == 0 {
		if _, _, err := TenantSigningKey(slug); err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if entries, err = tenantJWKSEntries(slug); err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	}

	keys := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, map[string]interface{}{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": e.kid,
			"n":   base64.RawURLEncoding.EncodeToString(e.pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(e.pub.E)).Bytes()),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": keys})
}

func handleRootJWKS(w http.ResponseWriter, r *http.Request) {
	handleJWKSCore(w, r, "")
}

func handleTenantJWKS(w http.ResponseWriter, r *http.Request) {
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	handleJWKSCore(w, r, slug)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		handleRootJWKS(w, r)
		return
	}
	handleTenantJWKS(w, r)
}

func handleJWKSRFC8414(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	if _, found := database.ClientIDForSlug(slug); !found {
		http.NotFound(w, r)
		return
	}
	handleJWKSCore(w, r, slug)
}

func handleAuthorizeCore(w http.ResponseWriter, r *http.Request, slug, tenantClientID string) {
	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	prompt := r.URL.Query().Get("prompt")

	if clientID == "" || redirectURI == "" {
		http.Error(w, "invalid_request: 缺少必需参数 client_id 或 redirect_uri", http.StatusBadRequest)
		return
	}

	// 校验 client_id 与 redirect_uri（防开放重定向）
	if !validateClient(clientID, redirectURI) {
		http.Error(w, "unauthorized_client: 未注册的 client_id 或 redirect_uri 不合法", http.StatusForbidden)
		return
	}

	// 租户隔离校验：仅在租户端点时校验 client_id 必须与该 slug 绑定的应用一致
	if slug != "" && tenantClientID != "" && clientID != tenantClientID {
		http.Error(w, "unauthorized_client: client_id 与该 Issuer 不匹配", http.StatusForbidden)
		return
	}

	// 以下错误已确认 redirect_uri 合法，按 RFC 6749 规范重定向
	if responseType != "code" {
		redirectAuthorizeError(w, r, redirectURI, state, "unsupported_response_type", "仅支持 authorization_code 流程")
		return
	}
	if !strings.Contains(scope, "openid") {
		redirectAuthorizeError(w, r, redirectURI, state, "invalid_scope", "scope 必须包含 openid")
		return
	}
	if codeChallenge != "" && codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		redirectAuthorizeError(w, r, redirectURI, state, "invalid_request", "code_challenge_method 仅支持 S256")
		return
	}
	if prompt == "none" {
		redirectAuthorizeError(w, r, redirectURI, state, "login_required", "用户需要进行群内核验")
		return
	}

	ttlStr := database.GetSetting("code_ttl", "180")
	ttl, _ := strconv.Atoi(ttlStr)
	if ttl <= 0 {
		ttl = 180
	}

	branding := database.GetClientBranding(clientID)
	groupID := branding["target_group_id"]
	if groupID == "" {
		groupID = database.GetSetting("target_group_id", "")
	}

	scopes := strings.Fields(scope)

	sess, err := session.DefaultManager.CreateSessionWithOptions(session.CreateSessionOptions{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               nonce,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		GroupID:             groupID,
		IssuerSlug:          slug,
		TTLSeconds:          ttl,
	})
	if err != nil {
		http.Error(w, "server_error: 会话创建失败", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login?session_id="+sess.SessionID, http.StatusFound)
}

func handleRootAuthorize(w http.ResponseWriter, r *http.Request) {
	handleAuthorizeCore(w, r, "", "")
}

func handleTenantAuthorize(w http.ResponseWriter, r *http.Request) {
	slug, tenantClientID, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	handleAuthorizeCore(w, r, slug, tenantClientID)
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		handleRootAuthorize(w, r)
		return
	}
	handleTenantAuthorize(w, r)
}

func handleTokenCore(w http.ResponseWriter, r *http.Request, slug, tenantClientID string) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// 支持 Basic Auth
	if clientID == "" {
		if bID, bSec, ok := r.BasicAuth(); ok {
			clientID = bID
			clientSecret = bSec
		}
	}

	switch grantType {
	case "authorization_code":
		handleAuthorizationCodeGrant(w, r, slug, tenantClientID, clientID, clientSecret)
	case "refresh_token":
		handleRefreshTokenGrant(w, r, slug, tenantClientID, clientID, clientSecret)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "支持的 grant_type 为 authorization_code 或 refresh_token",
		})
	}
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, slug, tenantClientID, clientID, clientSecret string) {
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	sess, exchanged := session.DefaultManager.ExchangeCode(code)
	if !exchanged {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	if sess.ClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}
	if tenantClientID != "" && sess.ClientID != tenantClientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if slug != "" && sess.IssuerSlug != "" && sess.IssuerSlug != slug {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
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

	signKey, signKid, err := TenantSigningKey(slug)
	if err != nil {
		log.Printf("[OIDC] 加载签名密钥失败 (slug=%q): %v", slug, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	issuer := buildIssuer(r, slug)
	now := time.Now()

	profile := identity.ProfileFor(identity.Identity{Provider: sess.Provider, UserID: sess.UserID})

	// 1. 签发独立的 Access Token（RS256 JWT）
	scopeStr := strings.Join(sess.Scopes, " ")
	if scopeStr == "" {
		scopeStr = "openid profile email"
	}
	accessClaims := jwtLib.MapClaims{
		"iss":               issuer,
		"sub":               sess.UserID,
		"aud":               clientID,
		"client_id":         clientID,
		"exp":               now.Add(time.Hour).Unix(),
		"iat":               now.Unix(),
		"token_use":         "access_token",
		"scope":             scopeStr,
		"identity_provider": sess.Provider,
	}
	accessTokenObj := jwtLib.NewWithClaims(jwtLib.SigningMethodRS256, accessClaims)
	accessTokenObj.Header["kid"] = signKid
	accessTokenStr, err := accessTokenObj.SignedString(signKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// 2. 签发 ID Token（包含 at_hash、nonce 与 auth_time）
	authTime := sess.AuthTime
	if authTime <= 0 {
		authTime = now.Unix()
	}
	idClaims := jwtLib.MapClaims{
		"iss":               issuer,
		"sub":               sess.UserID,
		"aud":               clientID,
		"exp":               now.Add(time.Hour).Unix(),
		"iat":               now.Unix(),
		"auth_time":         authTime,
		"identity_provider": sess.Provider,
		"at_hash":           computeAtHash(accessTokenStr),
	}
	if sess.Nonce != "" {
		idClaims["nonce"] = sess.Nonce
	}
	for k, v := range profile.Claims() {
		idClaims[k] = v
	}

	idTokenObj := jwtLib.NewWithClaims(jwtLib.SigningMethodRS256, idClaims)
	idTokenObj.Header["kid"] = signKid
	idTokenStr, err := idTokenObj.SignedString(signKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	resp := map[string]interface{}{
		"access_token": accessTokenStr,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idTokenStr,
		"scope":        scopeStr,
	}

	// 3. 当请求 offline_access 时签发 Refresh Token
	if hasScope(sess.Scopes, "offline_access") {
		rt, err := generateRandomHex(32)
		if err == nil {
			expiresAt := now.Add(30 * 24 * time.Hour)
			if err := database.StoreRefreshToken(rt, clientID, sess.UserID, sess.Provider, scopeStr, slug, expiresAt); err == nil {
				resp["refresh_token"] = rt
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, slug, tenantClientID, clientID, clientSecret string) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "missing refresh_token"})
		return
	}

	// 验证客户端凭证
	if !validateClientSecret(clientID, clientSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	row, err := database.GetRefreshToken(refreshToken)
	if err != nil || row.Revoked || time.Now().After(row.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "refresh token is invalid or expired",
		})
		return
	}

	if row.ClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "client_id mismatch",
		})
		return
	}

	if slug != "" && row.IssuerSlug != "" && row.IssuerSlug != slug {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "issuer mismatch",
		})
		return
	}

	// 轮换 Refresh Token（旧令牌吊销，签发新令牌）
	_ = database.RevokeRefreshToken(refreshToken)
	newRefreshToken, _ := generateRandomHex(32)
	now := time.Now()
	newExpiresAt := now.Add(30 * 24 * time.Hour)
	_ = database.StoreRefreshToken(newRefreshToken, clientID, row.UserID, row.Provider, row.Scopes, row.IssuerSlug, newExpiresAt)

	signKey, signKid, err := TenantSigningKey(slug)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	issuer := buildIssuer(r, slug)

	// 新 Access Token
	accessClaims := jwtLib.MapClaims{
		"iss":               issuer,
		"sub":               row.UserID,
		"aud":               clientID,
		"client_id":         clientID,
		"exp":               now.Add(time.Hour).Unix(),
		"iat":               now.Unix(),
		"token_use":         "access_token",
		"scope":             row.Scopes,
		"identity_provider": row.Provider,
	}
	accessTokenObj := jwtLib.NewWithClaims(jwtLib.SigningMethodRS256, accessClaims)
	accessTokenObj.Header["kid"] = signKid
	accessTokenStr, err := accessTokenObj.SignedString(signKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// 新 ID Token
	profile := identity.ProfileFor(identity.Identity{Provider: row.Provider, UserID: row.UserID})
	idClaims := jwtLib.MapClaims{
		"iss":               issuer,
		"sub":               row.UserID,
		"aud":               clientID,
		"exp":               now.Add(time.Hour).Unix(),
		"iat":               now.Unix(),
		"auth_time":         now.Unix(),
		"identity_provider": row.Provider,
		"at_hash":           computeAtHash(accessTokenStr),
	}
	for k, v := range profile.Claims() {
		idClaims[k] = v
	}
	idTokenObj := jwtLib.NewWithClaims(jwtLib.SigningMethodRS256, idClaims)
	idTokenObj.Header["kid"] = signKid
	idTokenStr, err := idTokenObj.SignedString(signKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	resp := map[string]interface{}{
		"access_token":  accessTokenStr,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      idTokenStr,
		"refresh_token": newRefreshToken,
		"scope":         row.Scopes,
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleRootToken(w http.ResponseWriter, r *http.Request) {
	handleTokenCore(w, r, "", "")
}

func handleTenantToken(w http.ResponseWriter, r *http.Request) {
	slug, tenantClientID, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	handleTokenCore(w, r, slug, tenantClientID)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		handleRootToken(w, r)
		return
	}
	handleTenantToken(w, r)
}

func handleUserinfoCore(w http.ResponseWriter, r *http.Request, slug string) {
	var tokenStr string
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
	} else if r.Method == http.MethodPost {
		_ = r.ParseForm()
		tokenStr = r.FormValue("access_token")
	}

	if tokenStr == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := jwtLib.Parse(tokenStr, func(t *jwtLib.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtLib.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kidVal, _ := t.Header["kid"].(string)
		if kidVal == "" {
			return nil, fmt.Errorf("missing kid")
		}
		pub, found := tenantPublicKeyByKid(slug, kidVal)
		if !found {
			return nil, fmt.Errorf("unknown kid for issuer")
		}
		return pub, nil
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

	expectedIss := buildIssuer(r, slug)
	if iss, _ := claims["iss"].(string); iss != expectedIss {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return
	}

	sub, _ := claims["sub"].(string)
	provider, _ := claims["identity_provider"].(string)
	userInfo := identity.ProfileFor(identity.Identity{Provider: provider, UserID: sub}).Claims()
	userInfo["sub"] = sub
	userInfo["identity_provider"] = provider
	writeJSON(w, http.StatusOK, userInfo)
}

func handleRootUserinfo(w http.ResponseWriter, r *http.Request) {
	handleUserinfoCore(w, r, "")
}

func handleTenantUserinfo(w http.ResponseWriter, r *http.Request) {
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	handleUserinfoCore(w, r, slug)
}

func handleUserinfo(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		handleRootUserinfo(w, r)
		return
	}
	handleTenantUserinfo(w, r)
}

// handleRevokeCore 实现 RFC 7009 令牌注销端点
func handleRevokeCore(w http.ResponseWriter, r *http.Request, slug string) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" {
		if bID, bSec, ok := r.BasicAuth(); ok {
			clientID = bID
			clientSecret = bSec
		}
	}

	if clientID != "" && clientSecret != "" {
		if !validateClientSecret(clientID, clientSecret) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
	}

	token := r.FormValue("token")
	if token != "" {
		_ = database.RevokeRefreshToken(token)
	}

	w.WriteHeader(http.StatusOK)
}

func handleRootRevoke(w http.ResponseWriter, r *http.Request) {
	handleRevokeCore(w, r, "")
}

func handleTenantRevoke(w http.ResponseWriter, r *http.Request) {
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	handleRevokeCore(w, r, slug)
}

// handleIntrospectCore 实现 RFC 7662 令牌内省端点
func handleIntrospectCore(w http.ResponseWriter, r *http.Request, slug string) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" {
		if bID, bSec, ok := r.BasicAuth(); ok {
			clientID = bID
			clientSecret = bSec
		}
	}

	if !validateClientSecret(clientID, clientSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	tokenStr := r.FormValue("token")
	if tokenStr == "" {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}

	// 1. 尝试作为 Refresh Token 校验
	if rt, err := database.GetRefreshToken(tokenStr); err == nil {
		if !rt.Revoked && time.Now().Before(rt.ExpiresAt) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"active":     true,
				"scope":      rt.Scopes,
				"client_id":  rt.ClientID,
				"sub":        rt.UserID,
				"exp":        rt.ExpiresAt.Unix(),
				"token_type": "refresh_token",
				"iss":        buildIssuer(r, rt.IssuerSlug),
			})
			return
		}
	}

	// 2. 尝试作为 JWT 校验
	token, err := jwtLib.Parse(tokenStr, func(t *jwtLib.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtLib.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected alg")
		}
		kidVal, _ := t.Header["kid"].(string)
		pub, found := tenantPublicKeyByKid(slug, kidVal)
		if !found {
			return nil, fmt.Errorf("unknown kid")
		}
		return pub, nil
	})

	if err == nil && token.Valid {
		if claims, ok := token.Claims.(jwtLib.MapClaims); ok {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"active":     true,
				"scope":      claims["scope"],
				"client_id":  claims["client_id"],
				"sub":        claims["sub"],
				"exp":        claims["exp"],
				"iat":        claims["iat"],
				"iss":        claims["iss"],
				"token_type": "Bearer",
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]bool{"active": false})
}

func handleRootIntrospect(w http.ResponseWriter, r *http.Request) {
	handleIntrospectCore(w, r, "")
}

func handleTenantIntrospect(w http.ResponseWriter, r *http.Request) {
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	handleIntrospectCore(w, r, slug)
}

// handleLogoutCore 实现 OIDC RP-Initiated Logout 1.0 登出端点
func handleLogoutCore(w http.ResponseWriter, r *http.Request, slug string) {
	postLogoutURI := r.URL.Query().Get("post_logout_redirect_uri")
	state := r.URL.Query().Get("state")
	idTokenHint := r.URL.Query().Get("id_token_hint")

	if idTokenHint != "" {
		token, _ := jwtLib.Parse(idTokenHint, func(t *jwtLib.Token) (interface{}, error) {
			kidVal, _ := t.Header["kid"].(string)
			pub, found := tenantPublicKeyByKid(slug, kidVal)
			if !found {
				return nil, fmt.Errorf("unknown kid")
			}
			return pub, nil
		})
		if token != nil {
			if claims, ok := token.Claims.(jwtLib.MapClaims); ok {
				sub, _ := claims["sub"].(string)
				aud, _ := claims["aud"].(string)
				if sub != "" && aud != "" {
					_ = database.RevokeClientUserRefreshTokens(aud, sub)
				}
			}
		}
	}

	if postLogoutURI != "" {
		u, err := url.Parse(postLogoutURI)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			if state != "" {
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
			}
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>已安全退出 - OneAuth</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 40px; text-align: center; max-width: 420px; width: 90%; }
        h1 { font-size: 1.5rem; margin-bottom: 12px; }
        p { color: #94a3b8; font-size: 0.95rem; margin-bottom: 24px; line-height: 1.5; }
        .btn { display: inline-block; padding: 10px 24px; border-radius: 10px; background: #3b82f6; color: #fff; text-decoration: none; font-size: 0.9rem; font-weight: 600; }
    </style>
</head>
<body>
    <div class="card">
        <h1>👋 已成功登出</h1>
        <p>您已安全退出认证会话。如需重新使用，请通过业务系统重新发起登录。</p>
        <a class="btn" href="/">返回首页</a>
    </div>
</body>
</html>`
	_, _ = w.Write([]byte(html))
}

func handleRootLogout(w http.ResponseWriter, r *http.Request) {
	handleLogoutCore(w, r, "")
}

func handleTenantLogout(w http.ResponseWriter, r *http.Request) {
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	handleLogoutCore(w, r, slug)
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

// handleSessionStatus 供登录页在 SSE 断开重连或不支持 SSE 的环境中轮询会话状态，保证无感更新不中断
func handleSessionStatus(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	sess, exists := session.DefaultManager.GetSession(sessionID)
	if !exists {
		writeJSON(w, http.StatusOK, map[string]string{"status": "not_found"})
		return
	}
	if time.Now().After(sess.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "expired"})
		return
	}
	if sess.Status == session.StatusVerified {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "verified",
			"redirect": fmt.Sprintf("/api/session/callback?session_id=%s", sessionID),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "pending",
		"ttl":    int(time.Until(sess.ExpiresAt).Seconds()),
	})
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

// isTrustedProxy 检查对端 IP 是否属于本地回环或私有内网地址，
// 避免非信任的外网客户端直连时恶意伪造 X-Forwarded-Proto 协议头篡改 Issuer。
func isTrustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// getBaseURL 返回 scheme://host（不含路径），供拼接租户 Issuer 使用；
// 仅当底层为 TLS 或可信反代下发了 X-Forwarded-Proto 时才信任 https。
func getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if r.Header.Get("X-Forwarded-Proto") == "https" && isTrustedProxy(r.RemoteAddr) {
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
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	h := sha256.Sum256([]byte(password))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}

// HashSecret 对客户端密钥进行安全哈希（采用 bcrypt）
func HashSecret(secret string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}
