package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"oneauth/internal/database"
	"oneauth/internal/onebot"
	"oneauth/internal/session"
)

const adminSessionTTL = 24 * time.Hour

type adminClaims struct {
	Username string
	IssuedAt int64
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

// deleteOthers 吊销除 keep 外的全部会话：修改密码后强制其它终端重新登录。
func (s *adminSessionStore) deleteOthers(keep string) {
	s.mu.Lock()
	for token := range s.sessions {
		if token != keep {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()
}

// renew 滑动续期：活跃管理员不会被 24h 硬超时踢下线。只在剩余寿命不足一半时
// 才写一次（新值放回 map），避免每个请求都产生写锁竞争。
func (s *adminSessionStore) renew(token string, claim *adminClaims) {
	now := time.Now().Unix()
	if claim.Exp-now > int64(adminSessionTTL/time.Second)/2 {
		return
	}
	s.put(token, &adminClaims{
		Username: claim.Username,
		IssuedAt: now,
		Exp:      now + int64(adminSessionTTL/time.Second),
	})
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

// dummyHash 用于“用户不存在”的登录尝试：照样执行一次同代价的 bcrypt 比对，
// 抹平响应时间差，防止通过耗时差异枚举出有效管理员用户名。
var dummyHash = func() []byte {
	if h, err := bcrypt.GenerateFromPassword([]byte("oneauth-timing-equalizer"), bcrypt.DefaultCost); err == nil {
		return h
	}
	return []byte("$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5B0X8fSK0COhPt5PoW9UxJvGdF6rW")
}()

// ---- 登录限速 ----

const maxBuckets = 4096

type loginFails struct {
	stamps []time.Time
	until  time.Time // 锁定截止时间，零值表示未锁定
}

// loginLimiter 按来源 IP 记录登录失败：window 内失败达 max 次
// 即锁定 lock 时长，成功登录立即清零。bcrypt 信号量保护 CPU，限速器
// 再挡住在线爆破本身。
//
// 只按 RemoteAddr 取 IP，不信任 X-Forwarded-For：否则直连部署时可被伪造头
// 完全绕过。反代部署下同源 IP 共享一个桶，属于可接受的保守取舍。
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginFails
	window  time.Duration
	max     int
	lock    time.Duration
}

var limiter = newLoginLimiter()

func newLoginLimiter() *loginLimiter {
	l := &loginLimiter{
		entries: make(map[string]*loginFails),
		window:  5 * time.Minute,
		max:     5,
		lock:    15 * time.Minute,
	}
	go l.janitor()
	return l
}

// blocked 返回剩余锁定秒数；0 表示未锁定。锁定中但不足 1 秒也按 1 秒报，
// 避免截断成 0 让调用方误判为未锁定。
func (l *loginLimiter) blocked(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil || !time.Now().Before(e.until) {
		return 0
	}
	remain := int(time.Until(e.until).Seconds())
	if remain < 1 {
		remain = 1
	}
	return remain
}

func (l *loginLimiter) recordFailure(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= maxBuckets {
		l.pruneLocked(now)
	}
	e := l.entries[key]
	if e == nil {
		e = &loginFails{}
		l.entries[key] = e
	}
	// 锁定期间的新失败只延长观察，不重置锁定截止时间
	if now.Before(e.until) {
		return
	}
	fresh := e.stamps[:0]
	for _, t := range e.stamps {
		if now.Sub(t) < l.window {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, now)
	e.stamps = fresh
	if len(e.stamps) >= l.max {
		e.until = now.Add(l.lock)
		e.stamps = e.stamps[:0]
	}
}

func (l *loginLimiter) clear(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

func (l *loginLimiter) pruneLocked(now time.Time) {
	for k, e := range l.entries {
		stale := len(e.stamps) == 0 || now.Sub(e.stamps[len(e.stamps)-1]) >= l.window
		if stale && now.After(e.until) {
			delete(l.entries, k)
		}
	}
}

func (l *loginLimiter) janitor() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		l.mu.Lock()
		l.pruneLocked(now)
		l.mu.Unlock()
	}
}

// ---- 请求解析与响应工具 ----

const maxBodyBytes = 1 << 20 // 管理接口入参上限 1 MiB，防超大 body 打内存

var errBodyTooLarge = errors.New("请求体过大")

// decodeJSON 读取前先限死请求体大小。整体 ReadAll 后再反序列化：
// json.Decoder 在超限时不会把 *http.MaxBytesError 原样抛出（会吞成
// unexpected EOF），没法可靠区分“超大请求”和“非法 JSON”。
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errBodyTooLarge
		}
		return fmt.Errorf("读取请求体失败")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("请求体不是合法 JSON")
	}
	return nil
}

type ctxKey int

const (
	ctxKeyToken ctxKey = iota
	ctxKeyClaim
)

func claimFrom(r *http.Request) *adminClaims {
	claim, _ := r.Context().Value(ctxKeyClaim).(*adminClaims)
	return claim
}

// SecureHeaders 给管理后台页面与 API 统一附加安全响应头；API 响应一律
// no-store，防止 token 与管理数据被浏览器/中间层缓存。
func SecureHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[管理后台] JSON 响应写入失败: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// processStart 供 /api/admin/stats 计算真实服务运行时间。
var processStart = time.Now()

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/admin/login", SecureHeaders(handleAdminLogin))
	mux.HandleFunc("POST /api/admin/logout", SecureHeaders(authMiddleware(handleLogout)))
	mux.HandleFunc("GET /api/admin/stats", SecureHeaders(authMiddleware(handleStats)))
	mux.HandleFunc("GET /api/admin/settings", SecureHeaders(authMiddleware(handleGetSettings)))
	mux.HandleFunc("POST /api/admin/settings", SecureHeaders(authMiddleware(handleSaveSettings)))
	mux.HandleFunc("GET /api/admin/clients", SecureHeaders(authMiddleware(handleListClients)))
	mux.HandleFunc("POST /api/admin/clients", SecureHeaders(authMiddleware(handleCreateClient)))
	mux.HandleFunc("PUT /api/admin/clients/{id}", SecureHeaders(authMiddleware(handleUpdateClient)))
	mux.HandleFunc("DELETE /api/admin/clients/{id}", SecureHeaders(authMiddleware(handleDeleteClient)))
	mux.HandleFunc("GET /api/admin/setup", SecureHeaders(handleSetupStatus))
	mux.HandleFunc("POST /api/admin/setup", SecureHeaders(handleInitialSetup))
	mux.HandleFunc("POST /api/admin/preview-login", SecureHeaders(authMiddleware(handlePreviewLogin)))
	mux.HandleFunc("POST /api/admin/password", SecureHeaders(authMiddleware(handleChangePassword)))
}

func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait := limiter.blocked(ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, http.StatusTooManyRequests,
			fmt.Sprintf("登录失败次数过多，已临时锁定，请 %d 秒后重试", wait))
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)

	var hash string
	err := database.DB.QueryRow("SELECT password_hash FROM admin_users WHERE username = ?", req.Username).Scan(&hash)
	if err != nil {
		_ = bcryptCompare(dummyHash, []byte(req.Password))
		limiter.recordFailure(ip)
		log.Printf("[管理后台] 登录失败（用户不存在）user=%q ip=%s", req.Username, ip)
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	if err := bcryptCompare([]byte(hash), []byte(req.Password)); err != nil {
		limiter.recordFailure(ip)
		log.Printf("[管理后台] 登录失败（密码错误）user=%q ip=%s", req.Username, ip)
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	limiter.clear(ip)
	token := generateToken()
	if token == "" {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	now := time.Now()
	adminStore.put(token, &adminClaims{
		Username: req.Username,
		IssuedAt: now.Unix(),
		Exp:      now.Add(adminSessionTTL).Unix(),
	})
	log.Printf("[管理后台] 管理员 %s 登录成功 ip=%s", req.Username, ip)
	writeJSON(w, http.StatusOK, map[string]string{"token": token, "username": req.Username})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if token, _ := r.Context().Value(ctxKeyToken).(string); token != "" {
		adminStore.delete(token)
	}
	if claim := claimFrom(r); claim != nil {
		log.Printf("[管理后台] 管理员 %s 已退出登录 ip=%s", claim.Username, clientIP(r))
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleStats 返回真实的运行时概览数据：服务运行时间、客户端数、内存会话
// 分布、OneBot 连接状态与进程资源占用，替代前端自制的假指标。
func handleStats(w http.ResponseWriter, r *http.Request) {
	var clientCount int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM oidc_clients").Scan(&clientCount); err != nil {
		clientCount = 0
	}

	sessStats := session.DefaultManager.Stats()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	writeJSON(w, http.StatusOK, map[string]any{
		"uptime_seconds": int64(time.Since(processStart).Seconds()),
		"started_at":     processStart.UTC().Format(time.RFC3339),
		"clients":        clientCount,
		"sessions": map[string]int{
			"pending":  sessStats.Pending,
			"verified": sessStats.Verified,
			"consumed": sessStats.Consumed,
			"total":    sessStats.Total,
		},
		"onebot": onebot.Status(),
		"runtime": map[string]any{
			"goroutines":    runtime.NumGoroutine(),
			"heap_alloc_mb": math.Round(float64(ms.HeapAlloc)/(1<<20)*10) / 10,
			"sys_mb":        math.Round(float64(ms.Sys)/(1<<20)*10) / 10,
			"go_version":    runtime.Version(),
		},
	})
}

// handleSetupStatus 供登录弹窗判断当前是走"首次初始化"还是"日常登录"分支：
// 前端在展示登录弹窗之前先查一次，管理员表为空则渲染初始化表单。
func handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM admin_users").Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"initialized": count > 0})
}

func handleInitialSetup(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait := limiter.blocked(ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, http.StatusTooManyRequests,
			fmt.Sprintf("尝试次数过多，已临时锁定，请 %d 秒后重试", wait))
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)

	if req.Username == "" || strings.ContainsAny(req.Username, " \t\r\n") || len(req.Username) > 64 {
		writeError(w, http.StatusBadRequest, "用户名不能为空且长度不超过 64 个字符")
		return
	}
	if len(req.Password) < 6 {
		writeError(w, http.StatusBadRequest, "密码长度至少需要 6 个字符")
		return
	}

	hash, err := bcryptHash([]byte(req.Password))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// “检查是否已有管理员”和“插入”合并成一条语句，消除两个并发 setup
	// 同时通过 COUNT 检查的竞态；username 主键兜底。
	res, err := database.WriteDB.Exec(`
		INSERT INTO admin_users (username, password_hash)
		SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM admin_users)
	`, req.Username, string(hash))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		limiter.recordFailure(ip)
		log.Printf("[管理后台] 初始化被拒绝（管理员已存在）ip=%s", ip)
		writeError(w, http.StatusForbidden, "管理员已存在，禁止重复初始化")
		return
	}

	log.Printf("[管理后台] 管理员 %s 初始化创建成功 ip=%s", req.Username, ip)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handlePreviewLogin 供管理后台"预览登录页"按钮使用：/login 路由强依赖一个
// 真实存在的 session_id（只能从完整走一遍 /authorize 拿到），管理员直接打开
// /login 必然命中 400。这里代其创建一个不绑定任何 OIDC 客户端的一次性会话
// （client_id 留空，GetClientBranding 查不到对应客户端时会落回全局设置，
// 与预览"当前全局配置效果"的诉求一致），返回 session_id 供前端跳转。
func handlePreviewLogin(w http.ResponseWriter, r *http.Request) {
	ttlStr := database.GetSetting("code_ttl", "180")
	ttl, _ := strconv.Atoi(ttlStr)
	if ttl <= 0 {
		ttl = 180
	}
	sess, err := session.DefaultManager.CreateSession("", "", "", "", ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "预览会话创建失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_id": sess.SessionID})
}

// ---- 系统设置 ----

var allowedSettings = map[string]bool{
	"site_name":       true,
	"prompt_text":     true,
	"background_url":  true,
	"custom_css":      true,
	"target_group_id": true,
	"onebot_token":    true,
	"code_ttl":        true,
	"site_logo":       true,
	"demo_enabled":    true,
}

func settingLabel(key string) string {
	labels := map[string]string{
		"site_name":       "站点名称",
		"prompt_text":     "提示文案",
		"background_url":  "背景图 URL",
		"custom_css":      "自定义 CSS",
		"target_group_id": "QQ 群号",
		"onebot_token":    "OneBot Token",
		"code_ttl":        "验证码有效期",
		"site_logo":       "站点 Logo URL",
		"demo_enabled":    "内置体验应用开关",
	}
	if l, ok := labels[key]; ok {
		return l
	}
	return key
}

func checkLength(label, val string, maxRunes int) error {
	if len([]rune(val)) > maxRunes {
		return fmt.Errorf("%s 长度不能超过 %d 个字符", label, maxRunes)
	}
	return nil
}

// validateSetting 在写库前校验设置值：非法值此前会被静默保存，直到登录页
// 或机器人处理链路上才以难以排查的方式失效。
func validateSetting(key, val string) error {
	switch key {
	case "site_name":
		return checkLength(settingLabel(key), val, 100)
	case "prompt_text":
		return checkLength(settingLabel(key), val, 200)
	case "custom_css":
		return checkLength(settingLabel(key), val, 64<<10)
	case "onebot_token":
		return checkLength(settingLabel(key), val, 128)
	case "background_url", "site_logo":
		if val == "" {
			return nil
		}
		if err := checkLength(settingLabel(key), val, 2048); err != nil {
			return err
		}
		u, err := url.Parse(val)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New(settingLabel(key) + " 必须是 http(s) 直链")
		}
		return nil
	case "target_group_id":
		if val == "" {
			return nil
		}
		if _, err := strconv.ParseUint(val, 10, 64); err != nil {
			return errors.New("QQ 群号必须是纯数字")
		}
		return nil
	case "code_ttl":
		if val == "" {
			return nil
		}
		if n, err := strconv.Atoi(val); err != nil || n < 10 || n > 3600 {
			return errors.New("验证码有效期须为 10~3600 秒")
		}
		return nil
	case "demo_enabled":
		if val != "true" && val != "false" {
			return errors.New(settingLabel(key) + " 只能为 true 或 false")
		}
		return nil
	}
	return fmt.Errorf("不支持的设置项: %s", key)
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
		"site_logo":       database.GetSetting("site_logo", ""),
		"demo_enabled":    database.GetSetting("demo_enabled", "true"),
	}
	writeJSON(w, http.StatusOK, settings)
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 先整体校验再落库，避免一半合法一半非法造成“部分保存”。
	for k, v := range req {
		if !allowedSettings[k] {
			writeError(w, http.StatusBadRequest, "不支持的设置项: "+k)
			return
		}
		if err := validateSetting(k, v); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "field": k})
			return
		}
	}

	for k, v := range req {
		if err := database.SetSetting(k, v); err != nil {
			log.Printf("[管理后台] 写入设置 %s 失败: %v", k, err)
			writeError(w, http.StatusInternalServerError, "保存设置失败: "+settingLabel(k))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- 管理员密码 ----

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	claim := claimFrom(r)
	if claim == nil || claim.Username == "" {
		writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(req.NewPassword) < 6 {
		writeError(w, http.StatusBadRequest, "新密码长度至少需要 6 个字符")
		return
	}

	var hash string
	err := database.DB.QueryRow("SELECT password_hash FROM admin_users WHERE username = ?", claim.Username).Scan(&hash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "用户不存在")
		return
	}

	if err := bcryptCompare([]byte(hash), []byte(req.OldPassword)); err != nil {
		log.Printf("[管理后台] 管理员 %s 修改密码失败（原密码错误）ip=%s", claim.Username, clientIP(r))
		writeError(w, http.StatusForbidden, "原密码错误")
		return
	}

	newHash, err := bcryptHash([]byte(req.NewPassword))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "加密错误")
		return
	}

	if _, err = database.WriteDB.Exec("UPDATE admin_users SET password_hash = ? WHERE username = ?", string(newHash), claim.Username); err != nil {
		writeError(w, http.StatusInternalServerError, "更新失败")
		return
	}

	// 吊销其它终端的会话，当前终端由前端引导重新登录。
	if token, _ := r.Context().Value(ctxKeyToken).(string); token != "" {
		adminStore.deleteOthers(token)
	}
	log.Printf("[管理后台] 管理员 %s 密码修改成功 ip=%s", claim.Username, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "密码修改成功"})
}

// ---- OIDC 客户端管理 ----

// ClientInfo 的品牌字段为可选项：空串表示继承全局设置，登录页按接入的
// 项目自动呈现各自外观。
type ClientInfo struct {
	ClientID      string `json:"client_id"`
	ClientName    string `json:"client_name"`
	RedirectURIs  string `json:"redirect_uris"`
	CreatedAt     string `json:"created_at"`
	DisplayName   string `json:"display_name"`
	BackgroundURL string `json:"background_url"`
	PromptText    string `json:"prompt_text"`
	CustomCSS     string `json:"custom_css"`
}

type clientRequest struct {
	ClientName    string `json:"client_name"`
	RedirectURIs  string `json:"redirect_uris"`
	DisplayName   string `json:"display_name"`
	BackgroundURL string `json:"background_url"`
	PromptText    string `json:"prompt_text"`
	CustomCSS     string `json:"custom_css"`
}

// validateClientRequest 校验并规范一个客户端创建/编辑请求；品牌字段复用
// 设置项校验（URL scheme 白名单、长度上限），空串 = 继承全局。
func validateClientRequest(req *clientRequest) error {
	req.ClientName = strings.TrimSpace(req.ClientName)
	if req.ClientName == "" {
		return errors.New("应用名称不能为空")
	}
	if len([]rune(req.ClientName)) > 100 {
		return errors.New("应用名称不能超过 100 个字符")
	}
	uris, err := validateRedirectURIs(req.RedirectURIs)
	if err != nil {
		return err
	}
	req.RedirectURIs = strings.Join(uris, ",")
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if len([]rune(req.DisplayName)) > 100 {
		return errors.New("登录页显示名不能超过 100 个字符")
	}
	if req.BackgroundURL != "" {
		if err := validateSetting("background_url", req.BackgroundURL); err != nil {
			return err
		}
	}
	req.PromptText = strings.TrimSpace(req.PromptText)
	if err := validateSetting("prompt_text", req.PromptText); err != nil {
		return err
	}
	if err := validateSetting("custom_css", req.CustomCSS); err != nil {
		return err
	}
	return nil
}

func clientInfoFromRow(scan func(*string, *string, *string, *string, *string, *string, *string, *string)) ClientInfo {
	var id, name, uris, created, dn, bg, pt, css string
	scan(&id, &name, &uris, &created, &dn, &bg, &pt, &css)
	return ClientInfo{
		ClientID: id, ClientName: name, RedirectURIs: uris, CreatedAt: created,
		DisplayName: dn, BackgroundURL: bg, PromptText: pt, CustomCSS: css,
	}
}

const clientColumns = `client_id, client_name, redirect_uris, created_at,
	COALESCE(display_name, ''), COALESCE(background_url, ''),
	COALESCE(prompt_text, ''), COALESCE(custom_css, '')`

func handleListClients(w http.ResponseWriter, r *http.Request) {
	rows, err := database.DB.Query("SELECT " + clientColumns + " FROM oidc_clients ORDER BY created_at")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	defer rows.Close()

	clients := []ClientInfo{}
	for rows.Next() {
		var c ClientInfo
		if err := rows.Scan(&c.ClientID, &c.ClientName, &c.RedirectURIs, &c.CreatedAt,
			&c.DisplayName, &c.BackgroundURL, &c.PromptText, &c.CustomCSS); err != nil {
			continue
		}
		clients = append(clients, c)
	}
	writeJSON(w, http.StatusOK, clients)
}

// validateRedirectURIs 逐个校验回调地址：必须是合法 http(s) URL、无 fragment、
// 无空白符、不重复。授权码最终会重定向到这些地址，宽松校验等于开放重定向。
func validateRedirectURIs(raw string) ([]string, error) {
	list := strings.Split(raw, ",")
	if len(list) > 20 {
		return nil, errors.New("回调地址最多 20 个")
	}
	normalized := make([]string, 0, len(list))
	seen := make(map[string]bool, len(list))
	for _, item := range list {
		uri := strings.TrimSpace(item)
		if uri == "" {
			return nil, errors.New("回调地址不能为空（多个地址用英文逗号分隔）")
		}
		if strings.ContainsAny(uri, " \t\r\n") {
			return nil, fmt.Errorf("回调地址不能包含空白字符: %s", uri)
		}
		u, err := url.Parse(uri)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("回调地址必须是完整的 http(s) URL: %s", uri)
		}
		if u.Fragment != "" {
			return nil, fmt.Errorf("回调地址不能包含 # 片段: %s", uri)
		}
		if seen[uri] {
			return nil, fmt.Errorf("回调地址重复: %s", uri)
		}
		seen[uri] = true
		normalized = append(normalized, uri)
	}
	return normalized, nil
}

func handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req clientRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateClientRequest(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	clientID := generateClientID()
	clientSecret := generateClientSecret()
	if clientID == "" || clientSecret == "" {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	hash := sha256.Sum256([]byte(clientSecret))
	secretHash := base64.RawURLEncoding.EncodeToString(hash[:])

	_, err := database.WriteDB.Exec(`
		INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris,
			display_name, background_url, prompt_text, custom_css)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		clientID, secretHash, req.ClientName, req.RedirectURIs,
		req.DisplayName, req.BackgroundURL, req.PromptText, req.CustomCSS)
	if err != nil {
		log.Printf("[管理后台] 创建客户端失败: %v", err)
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	log.Printf("[管理后台] 创建 OIDC 客户端 %q (%s) ip=%s", req.ClientName, clientID, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"client_name":   req.ClientName,
	})
}

// handleUpdateClient 编辑一个已注册客户端的名称、回调地址与登录页品牌覆盖。
func handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Bad request")
		return
	}

	var req clientRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateClientRequest(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	res, err := database.WriteDB.Exec(`
		UPDATE oidc_clients SET client_name = ?, redirect_uris = ?,
			display_name = ?, background_url = ?, prompt_text = ?, custom_css = ?
		WHERE client_id = ?`,
		req.ClientName, req.RedirectURIs,
		req.DisplayName, req.BackgroundURL, req.PromptText, req.CustomCSS, id)
	if err != nil {
		log.Printf("[管理后台] 更新客户端 %s 失败: %v", id, err)
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "客户端不存在或已被移除")
		return
	}

	log.Printf("[管理后台] 更新 OIDC 客户端 %s ip=%s", id, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Bad request")
		return
	}

	res, err := database.WriteDB.Exec("DELETE FROM oidc_clients WHERE client_id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "客户端不存在或已被移除")
		return
	}

	log.Printf("[管理后台] 删除 OIDC 客户端 %s ip=%s", id, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- 鉴权与工具 ----

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")

		claim, ok := adminStore.get(token)
		if !ok || claim.Username == "" {
			writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		adminStore.renew(token, claim)

		ctx := context.WithValue(r.Context(), ctxKeyToken, token)
		ctx = context.WithValue(ctx, ctxKeyClaim, claim)
		next(w, r.WithContext(ctx))
	}
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败时宁可让调用方返回 500，也绝不发空/重复凭证
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateToken() string        { return randomToken(32) }
func generateClientID() string     { return "oa_" + randomToken(12) }
func generateClientSecret() string { return randomToken(32) }
