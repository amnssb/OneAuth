package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"oneauth/internal/database"
)

type adminClaims struct {
	Username string
	Exp      int64
}

// adminSessions 是普通 map，被并发的登录/鉴权请求读写（authMiddleware 还会
// 删除过期项），必须加锁，否则是数据竞争。过期项由 janitor 周期清理。
type adminSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*adminClaims
}

var adminStore = newAdminStore()

func newAdminStore() *adminSessionStore {
	s := &adminSessionStore{sessions: make(map[string]*adminClaims)}
	go s.janitor()
	return s
}

func (s *adminSessionStore) put(token string, claims *adminClaims) {
	s.mu.Lock()
	s.sessions[token] = claims
	s.mu.Unlock()
}

func (s *adminSessionStore) get(token string) (*adminClaims, bool) {
	s.mu.RLock()
	claim, ok := s.sessions[token]
	s.mu.RUnlock()
	if ok && time.Now().Unix() > claim.Exp {
		s.delete(token)
		return nil, false
	}
	return claim, ok
}

func (s *adminSessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func (s *adminSessionStore) janitor() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		s.mu.Lock()
		for token, claim := range s.sessions {
			if now > claim.Exp {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}

// bcrypt 是 CPU 密集操作（DefaultCost 约 50~100ms），无限制地并发执行会被
// 登录接口打满 CPU。信号量把同时进行的哈希/比对限制在核数以内。
var bcryptSlots = make(chan struct{}, max(2, runtime.NumCPU()))

func bcryptCompare(hash, password []byte) error {
	bcryptSlots <- struct{}{}
	defer func() { <-bcryptSlots }()
	return bcrypt.CompareHashAndPassword(hash, password)
}

func bcryptHash(password []byte) ([]byte, error) {
	bcryptSlots <- struct{}{}
	defer func() { <-bcryptSlots }()
	return bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
}

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/admin/login", handleAdminLogin)
	mux.HandleFunc("GET /api/admin/settings", authMiddleware(handleGetSettings))
	mux.HandleFunc("POST /api/admin/settings", authMiddleware(handleSaveSettings))
	mux.HandleFunc("GET /api/admin/clients", authMiddleware(handleListClients))
	mux.HandleFunc("POST /api/admin/clients", authMiddleware(handleCreateClient))
	mux.HandleFunc("DELETE /api/admin/clients/{id}", authMiddleware(handleDeleteClient))
	mux.HandleFunc("POST /api/admin/setup", handleInitialSetup)
	mux.HandleFunc("POST /api/admin/password", authMiddleware(handleChangePassword))
}

func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var hash string
	err := database.DB.QueryRow("SELECT password_hash FROM admin_users WHERE username = ?", req.Username).Scan(&hash)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := bcryptCompare([]byte(hash), []byte(req.Password)); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := generateToken()
	adminStore.put(token, &adminClaims{
		Username: req.Username,
		Exp:      time.Now().Add(24 * time.Hour).Unix(),
	})

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func handleInitialSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if req.Username == "" || len(req.Password) < 6 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	hash, err := bcryptHash([]byte(req.Password))
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// “检查是否已有管理员”和“插入”合并成一条语句，消除两个并发 setup
	// 同时通过 COUNT 检查的竞态；username 主键兜底。
	res, err := database.WriteDB.Exec(`
		INSERT INTO admin_users (username, password_hash)
		SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM admin_users)
	`, req.Username, string(hash))
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	log.Println("Admin user created")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings := map[string]string{
		"site_name":       database.GetSetting("site_name", ""),
		"prompt_text":     database.GetSetting("prompt_text", "请发送验证码至群"),
		"background_url":  database.GetSetting("background_url", ""),
		"custom_css":      database.GetSetting("custom_css", ""),
		"target_group_id": database.GetSetting("target_group_id", ""),
		"onebot_token":    database.GetSetting("onebot_token", ""),
		"code_ttl":        database.GetSetting("code_ttl", ""),
	}
	writeJSON(w, http.StatusOK, settings)
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	allowedKeys := map[string]bool{
		"site_name":       true,
		"prompt_text":     true,
		"background_url":  true,
		"custom_css":      true,
		"target_group_id": true,
		"onebot_token":    true,
		"code_ttl":        true,
		"site_logo":       true,
	}

	for k, v := range req {
		if allowedKeys[k] {
			if err := database.SetSetting(k, v); err != nil {
				log.Printf("[管理后台] 写入设置 %s 失败: %v", k, err)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claim, ok := adminStore.get(auth)
	if !ok || claim.Username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 6 {
		http.Error(w, "新密码长度至少需要 6 个字符", http.StatusBadRequest)
		return
	}

	var hash string
	err := database.DB.QueryRow("SELECT password_hash FROM admin_users WHERE username = ?", claim.Username).Scan(&hash)
	if err != nil {
		http.Error(w, "用户不存在", http.StatusUnauthorized)
		return
	}

	if err := bcryptCompare([]byte(hash), []byte(req.OldPassword)); err != nil {
		http.Error(w, "原密码错误", http.StatusForbidden)
		return
	}

	newHash, err := bcryptHash([]byte(req.NewPassword))
	if err != nil {
		http.Error(w, "加密错误", http.StatusInternalServerError)
		return
	}

	_, err = database.WriteDB.Exec("UPDATE admin_users SET password_hash = ? WHERE username = ?", string(newHash), claim.Username)
	if err != nil {
		http.Error(w, "更新失败", http.StatusInternalServerError)
		return
	}

	log.Printf("[管理后台] 管理员 %s 密码修改成功\n", claim.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "密码修改成功"})
}

type ClientInfo struct {
	ClientID     string `json:"client_id"`
	ClientName   string `json:"client_name"`
	RedirectURIs string `json:"redirect_uris"`
	CreatedAt    string `json:"created_at"`
}

func handleListClients(w http.ResponseWriter, r *http.Request) {
	rows, err := database.DB.Query("SELECT client_id, client_name, redirect_uris, created_at FROM oidc_clients")
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var clients []ClientInfo
	for rows.Next() {
		var c ClientInfo
		if err := rows.Scan(&c.ClientID, &c.ClientName, &c.RedirectURIs, &c.CreatedAt); err != nil {
			continue
		}
		clients = append(clients, c)
	}
	if clients == nil {
		clients = []ClientInfo{}
	}
	writeJSON(w, http.StatusOK, clients)
}

func handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientName   string `json:"client_name"`
		RedirectURIs string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	clientID := generateClientID()
	clientSecret := generateClientSecret()

	hash := sha256.Sum256([]byte(clientSecret))
	secretHash := base64.RawURLEncoding.EncodeToString(hash[:])

	_, err := database.WriteDB.Exec("INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris) VALUES (?, ?, ?, ?)",
		clientID, secretHash, req.ClientName, req.RedirectURIs)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"client_name":   req.ClientName,
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	_, err := database.WriteDB.Exec("DELETE FROM oidc_clients WHERE client_id = ?", id)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")

		claim, ok := adminStore.get(token)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if claim.Username == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateClientID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "oa_" + base64.URLEncoding.EncodeToString(b)
}

func generateClientSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
