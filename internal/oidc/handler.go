package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	jwtLib "github.com/golang-jwt/jwt/v5"

	"oneauth/internal/database"
	"oneauth/internal/identity"
	"oneauth/internal/session"
)

// InitKeys 保留为兼容旧调用入口的空操作：多 Issuer 强制迁移后，签名密钥
// 一律按 issuer_slug 从 SQLite 惰性加载/生成（见 keys.go），不再使用全局
// 单文件密钥。keyPath 参数仅为保持 main.go 调用签名不变而保留。
func InitKeys(keyPath string) {
	log.Printf("[OIDC] 多 Issuer 模式：签名密钥按应用（issuer_slug）独立管理，全局密钥文件已停用")
}

func computeKID(pub *rsa.PublicKey) string {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("[OIDC] 公钥序列化失败: %v", err)
	}
	hash := sha256.Sum256(derBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:8])
}

// corsMetadata 允许任意来源跨域读取公开的发现文档与 JWKS。OIDC Discovery
// 规范要求发现端点支持 CORS，否则浏览器端发起的“自动发现”（前端直接
// fetch 这两个 URL）会被跨域策略拦下；两者均为公开元数据，不含凭证，
// 通配来源即可。顺带放行 OPTIONS 预检——mux 只注册了 GET，预检原本 405。
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

// tenantMux 承载所有 /{slug}/... 追加式租户端点。它必须与主 mux 分开：
// Go 1.22 ServeMux 认为两段通配（如 /{slug}/authorize）与子树前缀
// （如 /static/）互不更具体而拒绝共存并 panic。分开注册 + Wrap 里按首段
// 分流，既保留 https://host/{slug} 的 Issuer 形态，又规避该冲突。
var tenantMux = func() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /{slug}/.well-known/openid-configuration", corsMetadata(handleDiscovery))
	m.HandleFunc("OPTIONS /{slug}/.well-known/openid-configuration", corsMetadata(handleDiscovery))
	m.HandleFunc("GET /{slug}/.well-known/jwks.json", corsMetadata(handleJWKS))
	m.HandleFunc("OPTIONS /{slug}/.well-known/jwks.json", corsMetadata(handleJWKS))
	m.HandleFunc("GET /{slug}/authorize", handleAuthorize)
	m.HandleFunc("POST /{slug}/token", handleToken)
	m.HandleFunc("GET /{slug}/userinfo", handleUserinfo)
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
}

// RegisterRoutes 在主 mux 上注册与 issuer 无关的固定端点：RFC 8414 插入式
// 发现路径（固定 /.well-known 前缀，不与 /static/ 冲突）、根发现指引、以及
// 会话相关的 SSE/callback。/{slug}/... 追加式端点由 tenantMux 承载，经 Wrap
// 分流，不在此注册。
func RegisterRoutes(mux *http.ServeMux) {
	// RFC 8414 插入式发现路径（部分客户端库把 .well-known 插到 issuer 路径
	// 之前），与追加式内容一致，最大化兼容。固定前缀，不触发通配冲突。
	mux.HandleFunc("GET /.well-known/openid-configuration/{slug}", corsMetadata(handleDiscovery))
	mux.HandleFunc("GET /.well-known/jwks.json/{slug}", corsMetadata(handleJWKS))

	// 根发现端点：多 Issuer 下不存在“全局 issuer”，返回明确指引而非 404，
	// 方便存量接入方自助排障。
	mux.HandleFunc("GET /.well-known/openid-configuration", handleRootDiscoveryGone)

	// 会话相关端点（与 issuer 无关，登录页/SSE 共用）。
	mux.HandleFunc("GET /api/session/stream", handleSSE)
	mux.HandleFunc("GET /api/session/callback", handleSessionCallback)
}

// Wrap 把主 mux 包成最终 http.Handler：请求首段命中固定路由 → 主 mux；
// 否则视为 issuer_slug → tenantMux。这样 /{slug}/... 租户端点与 /static/
// 等子树前缀就不必在同一个 mux 里共存。
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

// firstSegment 取路径的第一段（去掉前导 /），"/acme/authorize" -> "acme"，
// "/" -> ""。
func firstSegment(path string) string {
	path = strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return path
}

// resolveTenant 从请求路径通配段解析 issuer_slug 并反查 client_id。
// 失败时直接写 404 响应并返回 ok=false，调用方据此提前返回。
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

// tenantIssuer 构造租户 Issuer：scheme://host/{slug}。
func tenantIssuer(r *http.Request, slug string) string {
	return getBaseURL(r) + "/" + slug
}

func handleRootDiscoveryGone(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]string{
		"error":             "multi_tenant",
		"error_description": "本服务已启用多 Issuer：每个应用有独立的发现地址，请使用 " + getBaseURL(r) + "/{应用的 issuer_slug}/.well-known/openid-configuration",
	})
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}
	issuer := tenantIssuer(r, slug)
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
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}

	entries, err := tenantJWKSEntries(slug)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	// 尚未生成过密钥（例如刚回填 slug 还未签发过 token）：惰性生成一把，
	// 保证 JWKS 端点始终返回可用公钥，下游可提前拉取。
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

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	_, tenantClientID, ok := resolveTenant(w, r)
	if !ok {
		return
	}

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
	// client_id 必须与该 issuer_slug 绑定的应用一致：防止用 A 应用的 slug
	// 端点为 B 应用发起授权，从而绕过租户隔离。
	if clientID != tenantClientID {
		http.Error(w, "unauthorized_client: client_id 与该 Issuer 不匹配", http.StatusForbidden)
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

	// 解析该应用绑定的核验群号：应用级 target_group_id 优先，为空则
	// 回落到全局设置。这样每个应用可以绑定各自独立的审核群。
	branding := database.GetClientBranding(clientID)
	groupID := branding["target_group_id"]
	if groupID == "" {
		groupID = database.GetSetting("target_group_id", "")
	}

	sess, err := session.DefaultManager.CreateSession(clientID, redirectURI, state, codeChallenge, groupID, ttl)
	if err != nil {
		http.Error(w, "server_error: 会话创建失败", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login?session_id="+sess.SessionID, http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	slug, tenantClientID, ok := resolveTenant(w, r)
	if !ok {
		return
	}

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

	sess, exchanged := session.DefaultManager.ExchangeCode(code)
	if !exchanged {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	if sess.ClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}
	// 授权码必须在其所属应用的 Issuer 端点兑换：授权码是在 /{slug}/authorize
	// 为该应用签发的，只能回到同一个 slug 的 /token 端点兑换。
	if sess.ClientID != tenantClientID {
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
		log.Printf("[OIDC] 加载租户 %s 签名密钥失败: %v", slug, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	issuer := tenantIssuer(r, slug)
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
	token.Header["kid"] = signKid
	idTokenStr, err := token.SignedString(signKey)
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
	slug, _, ok := resolveTenant(w, r)
	if !ok {
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// 按 token 头里的 kid 到「本租户」的密钥集合（在用 + 宽限期内退休）里
	// 取公钥验签；跨租户令牌的 kid 在此查不到，签名验证直接失败 —— 这是
	// 租户隔离的第一道闸。
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
			return nil, fmt.Errorf("unknown kid for tenant")
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

	// 第二道闸：iss 必须等于本 slug 的 Issuer，杜绝签名恰好匹配但来源租户
	// 不符的边界情况。
	expectedIss := tenantIssuer(r, slug)
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

// getBaseURL 返回 scheme://host（不含路径），供拼接租户 Issuer 使用；
// 尊重反代下发的 X-Forwarded-Proto。
func getBaseURL(r *http.Request) string {
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
