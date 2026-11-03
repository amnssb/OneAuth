package admin

import (
	"context"
	"crypto/rand"
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
	"oneauth/internal/audit"
	"oneauth/internal/database"
	"oneauth/internal/oidc"
	"oneauth/internal/onebot"
	"oneauth/internal/session"
	"oneauth/internal/version"
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
	stopChan chan struct{}
}

var adminStore = newAdminStore()

func newAdminStore() *adminSessionStore {
	s := &adminSessionStore{
		sessions: make(map[string]*adminClaims),
		stopChan: make(chan struct{}),
	}
	go s.janitor()
	return s
}

// Close 停止后台 janitor 协程
func (s *adminSessionStore) Close() {
	select {
	case <-s.stopChan:
	default:
		close(s.stopChan)
	}
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
	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
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
}

func (s *adminSessionStore) saveToDB() error {
	if database.WriteDB == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().Unix()
	tx, err := database.WriteDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM transient_admin_sessions"); err != nil {
		return err
	}

	stmt, err := tx.Prepare("INSERT INTO transient_admin_sessions (token, username, issued_at, exp) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	count := 0
	for token, claim := range s.sessions {
		if claim.Exp > now {
			if _, err := stmt.Exec(token, claim.Username, claim.IssuedAt, claim.Exp); err == nil {
				count++
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("[无感更新] 已持久化 %d 条管理员令牌用于平滑恢复", count)
	return nil
}

func (s *adminSessionStore) restoreFromDB() (int, error) {
	if database.DB == nil {
		return 0, nil
	}
	now := time.Now().Unix()
	rows, err := database.DB.Query("SELECT token, username, issued_at, exp FROM transient_admin_sessions WHERE exp > ?", now)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	restored := 0
	for rows.Next() {
		var token string
		var claim adminClaims
		if err := rows.Scan(&token, &claim.Username, &claim.IssuedAt, &claim.Exp); err != nil {
			continue
		}
		s.sessions[token] = &claim
		restored++
	}
	if err := rows.Err(); err != nil {
		log.Printf("[无感更新] 恢复管理员会话遍历异常: %v", err)
	}
	if restored > 0 {
		log.Printf("[无感更新] 已从备份成功恢复 %d 条管理员会话", restored)
	}
	go func() {
		if database.WriteDB != nil {
			_, _ = database.WriteDB.Exec("DELETE FROM transient_admin_sessions WHERE exp <= ?", now)
		}
	}()
	return restored, nil
}

// SaveAdminSessions 导出供平滑重启保存管理员登录状态
func SaveAdminSessions() error {
	return adminStore.saveToDB()
}

// RestoreAdminSessions 导出供启动时恢复管理员登录状态
func RestoreAdminSessions() (int, error) {
	return adminStore.restoreFromDB()
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

// loginLimiter 按来源 IP 与账号两个维度记录登录失败：window 内失败达
// max 次即锁定 lock 时长，成功登录立即清零。bcrypt 信号量保护 CPU，限速器
// 再挡住在线爆破本身。
//
// IP 维度：反代/CF 后面拿真实客户端 IP（仅当直连方是可信反代才采信
// 转发头，否则头可伪造），避免全站访客挤进同一个桶。
// 账号维度：锁账号本身，换 IP 爆破同一账号同样会被挡，同时不会因为
// 同出口 NAT 的其他访客失败而误伤自己。
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginFails
	window  time.Duration
	max     int
	lock    time.Duration
}

func ipKey(ip string) string        { return "ip:" + ip }
func accountKey(user string) string { return "acct:" + strings.ToLower(strings.TrimSpace(user)) }

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

// tryReserve 在 bcrypt 之前原子地预占一次尝试名额：调用方先预占、
// 再做慢速的 bcrypt 比对，失败不再补记。没有这一步，并发请求会
// 在 blocked() 检查时全部看到“未锁定”，再排队做 bcrypt——256 条
// 预连接 socket 能在同一个 5 次/窗口里拿到 256 次 401（TOCTOU，
// 实测 ~51x）。预占后第 max 次尝试即触发锁定，第 max+1 次起
// 直接 429，不再进入 bcrypt；在途尝试也被计入名额。
// 返回 false 表示已锁定，调用方应直接 429 且不再做 bcrypt。
func (l *loginLimiter) tryReserve(key string) bool {
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
	if now.Before(e.until) {
		return false
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
	return true
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
	ip, _ := clientIPInfo(r)
	return ip
}

// clientIPInfo 返回限流/审计用的客户端 IP 与“该 IP 是否可区分”。
// identifiable 为 false 的典型场景：服务跑在 Caddy 等反代后面，
// 直连方是 127.0.0.1，但反代没有透传任何转发头——此时所有访客
// 在本服务看来都是同一个 127.0.0.1。把这个共享地址当成限流桶，
// 攻击者 5 次失败就能把全体管理员锁定 15 分钟（全局 DoS）；
// 反过来，攻击者也能躲在这个桶后面让正常管理员替他分摊名额。
// 不可区分时调用方应跳过 IP 维度限流，只用账号维度限流，并
// 在日志里提示部署方检查反代透传配置。
func clientIPInfo(r *http.Request) (ip string, identifiable bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.TrimSpace(host)
	// 只有直连方是可信反代（回环/内网/链路本地）时才采信转发头：直连暴露
	// 在公网时 CF-Connecting-IP / X-Forwarded-For 可任意伪造，会把限流桶
	// 挪到攻击者指定的键上。可信反代后面的 Cloudflare 场景则取真实客户端
	// IP，避免所有人共享 RemoteAddr 这一个桶。
	if ip := net.ParseIP(host); ip != nil && isTrustedProxyAddr(ip) {
		if real := strings.TrimSpace(audit.ExtractClientIP(r)); real != "" && net.ParseIP(real) != nil && real != host {
			return real, true
		}
		// 直连方是反代但拿不到转发头：RemoteAddr 只是反代地址，
		// 不能代表任何一个真实访客。
		return host, false
	}
	return host, true
}

var sharedBucketWarned = struct {
	sync.Once
}{}

// warnSharedBucket 只在进程内提示一次，避免登录失败日志被刷屏。
func warnSharedBucket() {
	sharedBucketWarned.Do(func() {
		log.Printf("[管理后台] 警告：无法从反代透传头识别真实客户端 IP（直连方为回环/内网地址且无转发头），IP 维度限流已跳过、仅账号维度生效；请检查反代是否透传 X-Forwarded-For / CF-Connecting-IP，否则全体访客共享同一个限流桶")
	})
}

func isTrustedProxyAddr(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
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
	mux.HandleFunc("POST /api/admin/clients/{id}/rotate-key", SecureHeaders(authMiddleware(handleRotateClientKey)))
	mux.HandleFunc("GET /api/admin/setup", SecureHeaders(handleSetupStatus))
	mux.HandleFunc("POST /api/admin/setup", SecureHeaders(handleInitialSetup))
	mux.HandleFunc("POST /api/admin/preview-login", SecureHeaders(authMiddleware(handlePreviewLogin)))
	mux.HandleFunc("POST /api/admin/password", SecureHeaders(authMiddleware(handleChangePassword)))

	// 版本信息与无感热更管理端点
	mux.HandleFunc("GET /api/version", HandleVersion)
	mux.HandleFunc("GET /api/admin/version", SecureHeaders(authMiddleware(handleAdminVersion)))
	mux.HandleFunc("GET /api/admin/update/check", SecureHeaders(authMiddleware(handleCheckUpdate)))
	mux.HandleFunc("POST /api/admin/update/restart", SecureHeaders(authMiddleware(handleSeamlessRestart)))
	mux.HandleFunc("POST /api/admin/update/apply", SecureHeaders(authMiddleware(handleApplyUpdate)))

	// 审计日志接口
	mux.HandleFunc("GET /api/admin/audit-logs", SecureHeaders(authMiddleware(handleListAuditLogs)))
}

func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	ip, ipIdentifiable := clientIPInfo(r)
	if !ipIdentifiable {
		warnSharedBucket()
	}
	ipK := ipKey(ip)
	if ipIdentifiable {
		if wait := limiter.blocked(ipK); wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(wait))
			writeError(w, http.StatusTooManyRequests,
				fmt.Sprintf("登录失败次数过多，已临时锁定，请 %d 秒后重试", wait))
			return
		}
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

	acct := accountKey(req.Username)
	if wait := limiter.blocked(acct); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, http.StatusTooManyRequests,
			fmt.Sprintf("该账号登录失败次数过多，已临时锁定，请 %d 秒后重试", wait))
		return
	}

	// 在 bcrypt 之前原子预占名额（见 tryReserve）：失败尝试在进入
	// 慢速比对前就已计入，杜绝并发 TOCTOU 绕过；成功登录再清零。
	if ipIdentifiable && !limiter.tryReserve(ipK) {
		w.Header().Set("Retry-After", strconv.Itoa(limiter.blocked(ipK)))
		writeError(w, http.StatusTooManyRequests, "登录失败次数过多，已临时锁定，请稍后重试")
		return
	}
	if !limiter.tryReserve(acct) {
		w.Header().Set("Retry-After", strconv.Itoa(limiter.blocked(acct)))
		writeError(w, http.StatusTooManyRequests, "该账号登录失败次数过多，已临时锁定，请稍后重试")
		return
	}

	var hash string
	err := database.DB.QueryRow("SELECT password_hash FROM admin_users WHERE username = ?", req.Username).Scan(&hash)
	if err != nil {
		_ = bcryptCompare(dummyHash, []byte(req.Password))
		log.Printf("[管理后台] 登录失败（用户不存在）user=%q ip=%s", req.Username, ip)
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	if err := bcryptCompare([]byte(hash), []byte(req.Password)); err != nil {
		log.Printf("[管理后台] 登录失败（密码错误）user=%q ip=%s", req.Username, ip)
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	if ipIdentifiable {
		limiter.clear(ipK)
	}
	limiter.clear(acct)
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
	setAdminSessionCookie(w, r, token)
	log.Printf("[管理后台] 管理员 %s 登录成功 ip=%s", req.Username, ip)
	// token 仍在 JSON 里返回，供非浏览器 API 客户端使用；浏览器
	// 管理台不再读取它，凭据改由 HttpOnly Cookie 承载（见 admin.html）。
	writeJSON(w, http.StatusOK, map[string]string{"token": token, "username": req.Username})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if token, _ := r.Context().Value(ctxKeyToken).(string); token != "" {
		adminStore.delete(token)
	}
	clearAdminSessionCookie(w, r)
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
		"sessions": map[string]any{
			"pending":        sessStats.Pending,
			"verified":       sessStats.Verified,
			"consumed":       sessStats.Consumed,
			"total":          sessStats.Total,
			"created_total":  sessStats.CreatedTotal,
			"verified_total": sessStats.VerifiedTotal,
		},
		"onebot": onebot.Status(),
		"runtime": map[string]any{
			"goroutines":    runtime.NumGoroutine(),
			"heap_alloc_mb": math.Round(float64(ms.HeapAlloc)/(1<<20)*10) / 10,
			"sys_mb":        math.Round(float64(ms.Sys)/(1<<20)*10) / 10,
			"go_version":    runtime.Version(),
		},
		"version": version.Get(),
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
	ip, ipIdentifiable := clientIPInfo(r)
	if !ipIdentifiable {
		warnSharedBucket()
	}
	ipK := ipKey(ip)
	if ipIdentifiable {
		if wait := limiter.blocked(ipK); wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(wait))
			writeError(w, http.StatusTooManyRequests,
				fmt.Sprintf("尝试次数过多，已临时锁定，请 %d 秒后重试", wait))
			return
		}
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
	acct := accountKey(req.Username)
	if wait := limiter.blocked(acct); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, http.StatusTooManyRequests,
			fmt.Sprintf("尝试次数过多，已临时锁定，请 %d 秒后重试", wait))
		return
	}

	if req.Username == "" || strings.ContainsAny(req.Username, " \t\r\n") || len(req.Username) > 64 {
		writeError(w, http.StatusBadRequest, "用户名不能为空且长度不超过 64 个字符")
		return
	}
	if len(req.Password) < 6 {
		writeError(w, http.StatusBadRequest, "密码长度至少需要 6 个字符")
		return
	}

	// 与登录一样：bcrypt 之前先原子预占名额，杜绝并发绕过。
	if ipIdentifiable && !limiter.tryReserve(ipK) {
		writeError(w, http.StatusTooManyRequests, "尝试次数过多，已临时锁定，请稍后重试")
		return
	}
	if !limiter.tryReserve(acct) {
		writeError(w, http.StatusTooManyRequests, "尝试次数过多，已临时锁定，请稍后重试")
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
		log.Printf("[管理后台] 初始化被拒绝（管理员已存在）ip=%s", ip)
		writeError(w, http.StatusForbidden, "管理员已存在，禁止重复初始化")
		return
	}

	if ipIdentifiable {
		limiter.clear(ipK)
	}
	limiter.clear(acct)
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
	sess, err := session.DefaultManager.CreateSession("", "", "", "", database.GetSetting("target_group_id", ""), ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "预览会话创建失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_id": sess.SessionID})
}

// ---- 系统设置 ----

type settingSpec struct {
	Label    string
	Validate func(label, val string) error
}

func checkLength(label, val string, maxRunes int) error {
	if len([]rune(val)) > maxRunes {
		return fmt.Errorf("%s 长度不能超过 %d 个字符", label, maxRunes)
	}
	return nil
}

func validateURLOrEmpty(label, val string) error {
	if val == "" {
		return nil
	}
	if err := checkLength(label, val, 2048); err != nil {
		return err
	}
	u, err := url.Parse(val)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New(label + " 必须是 http(s) 直链")
	}
	return nil
}

var systemSettingsSpecs = map[string]settingSpec{
	"site_name": {
		Label: "站点名称",
		Validate: func(label, val string) error {
			return checkLength(label, val, 100)
		},
	},
	"prompt_text": {
		Label: "提示文案",
		Validate: func(label, val string) error {
			return checkLength(label, val, 200)
		},
	},
	"background_url": {
		Label:    "背景图 URL",
		Validate: validateURLOrEmpty,
	},
	"custom_css": {
		Label: "自定义 CSS",
		Validate: func(label, val string) error {
			return checkLength(label, val, 64<<10)
		},
	},
	"target_group_id": {
		Label: "默认 QQ 群号",
		Validate: func(label, val string) error {
			if val == "" {
				return nil
			}
			if _, err := strconv.ParseUint(val, 10, 64); err != nil {
				return errors.New("QQ 群号必须是纯数字")
			}
			return nil
		},
	},
	"onebot_token": {
		Label: "OneBot Token",
		Validate: func(label, val string) error {
			// 空值会让 WS 停摆、公开默认值会让 WS 形同虚设：两者
			// 都在入口拒绝，宁可管理员显式配一个强随机口令。
			if strings.TrimSpace(val) == "" {
				return errors.New(label + " 不能为空（清空将导致 OneBot WS 停用）")
			}
			if database.IsLegacyOnebotToken(val) {
				return errors.New(label + " 不能使用历史公开默认值")
			}
			if len(strings.TrimSpace(val)) < 16 {
				return errors.New(label + " 长度至少 16 个字符")
			}
			return checkLength(label, val, 128)
		},
	},
	// 反向 WS 的两道应用层收口：来源白名单 + 群成员身份二次核验。
	"onebot_ws_ip_allowlist": {
		Label: "WS 来源 IP 白名单",
		Validate: func(label, val string) error {
			if err := checkLength(label, val, 512); err != nil {
				return err
			}
			for _, item := range database.SplitURIList(val) {
				if strings.Contains(item, "/") {
					if _, _, err := net.ParseCIDR(item); err != nil {
						return fmt.Errorf("%s 含非法网段: %s", label, item)
					}
					continue
				}
				if net.ParseIP(item) == nil {
					return fmt.Errorf("%s 含非法 IP: %s", label, item)
				}
			}
			return nil
		},
	},
	"onebot_verify_member": {
		Label: "群成员二次核验",
		Validate: func(label, val string) error {
			if val != "true" && val != "false" {
				return errors.New(label + " 只能为 true 或 false")
			}
			return nil
		},
	},
	"code_ttl": {
		Label: "验证码有效期",
		Validate: func(label, val string) error {
			if val == "" {
				return nil
			}
			if n, err := strconv.Atoi(val); err != nil || n < 10 || n > 3600 {
				return errors.New("验证码有效期须为 10~3600 秒")
			}
			return nil
		},
	},
	"site_logo": {
		Label:    "站点 Logo URL",
		Validate: validateURLOrEmpty,
	},
	"demo_enabled": {
		Label: "内置体验应用开关",
		Validate: func(label, val string) error {
			if val != "true" && val != "false" {
				return errors.New(label + " 只能为 true 或 false")
			}
			return nil
		},
	},
	"update_check_url": {
		Label:    "更新检查地址",
		Validate: validateURLOrEmpty,
	},
	"update_proxy": {
		Label: "更新网络代理",
		Validate: func(label, val string) error {
			if val == "" {
				return nil
			}
			if err := checkLength(label, val, 1024); err != nil {
				return err
			}
			u, err := url.Parse(val)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
				return errors.New(label + " 必须是 http、https 或 socks5 代理地址")
			}
			return nil
		},
	},
}

var allowedSettings = func() map[string]bool {
	m := make(map[string]bool, len(systemSettingsSpecs))
	for k := range systemSettingsSpecs {
		m[k] = true
	}
	return m
}()

func settingLabel(key string) string {
	if spec, ok := systemSettingsSpecs[key]; ok {
		return spec.Label
	}
	return key
}

// validateSetting 在写库前校验设置值：非法值此前会被静默保存，直到登录页
// 或机器人处理链路上才以难以排查的方式失效。
func validateSetting(key, val string) error {
	if spec, ok := systemSettingsSpecs[key]; ok {
		return spec.Validate(spec.Label, val)
	}
	return fmt.Errorf("不支持的设置项: %s", key)
}

func handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings := map[string]string{
		"site_name":              database.GetSetting("site_name", ""),
		"prompt_text":            database.GetSetting("prompt_text", "请发送验证码至群"),
		"background_url":         database.GetSetting("background_url", ""),
		"custom_css":             database.GetSetting("custom_css", ""),
		"target_group_id":        database.GetSetting("target_group_id", ""),
		"onebot_token":           database.GetSetting("onebot_token", ""),
		"onebot_ws_ip_allowlist": database.GetSetting("onebot_ws_ip_allowlist", ""),
		"onebot_verify_member":   database.GetSetting("onebot_verify_member", "false"),
		"code_ttl":               database.GetSetting("code_ttl", ""),
		"site_logo":              database.GetSetting("site_logo", ""),
		"demo_enabled":           database.GetSetting("demo_enabled", "true"),
		"update_check_url":       database.GetSetting("update_check_url", "https://api.github.com/repos/amnssb/OneAuth/releases/latest"),
		"update_proxy":           database.GetSetting("update_proxy", ""),
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
// 项目自动呈现各自外观。IssuerSlug 是该应用独立 Issuer 的路径标识，
// Kid 是其当前在用签名密钥的 kid（供后台展示与轮换）。
type ClientInfo struct {
	ClientID       string `json:"client_id"`
	ClientName     string `json:"client_name"`
	RedirectURIs   string `json:"redirect_uris"`
	PostLogoutURIs string `json:"post_logout_redirect_uris"`
	CreatedAt      string `json:"created_at"`
	DisplayName    string `json:"display_name"`
	BackgroundURL  string `json:"background_url"`
	PromptText     string `json:"prompt_text"`
	CustomCSS      string `json:"custom_css"`
	TargetGroupID  string `json:"target_group_id"`
	IssuerSlug     string `json:"issuer_slug"`
	Kid            string `json:"kid"`
}

type clientRequest struct {
	ClientName     string `json:"client_name"`
	RedirectURIs   string `json:"redirect_uris"`
	PostLogoutURIs string `json:"post_logout_redirect_uris"`
	DisplayName    string `json:"display_name"`
	BackgroundURL  string `json:"background_url"`
	PromptText     string `json:"prompt_text"`
	CustomCSS      string `json:"custom_css"`
	TargetGroupID  string `json:"target_group_id"`
	// IssuerSlug 仅在创建时使用（创建后不可变），编辑请求会忽略此字段。
	IssuerSlug string `json:"issuer_slug"`
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

	// 登出跳转白名单（RP-Initiated Logout）：留空 = 只允许同源/相对路径；
	// 填了就必须是完整 http(s) 地址，否则登出时会被白名单校验拒掉。
	req.PostLogoutURIs = strings.TrimSpace(req.PostLogoutURIs)
	if req.PostLogoutURIs != "" {
		plist, err := validateRedirectURIs(req.PostLogoutURIs)
		if err != nil {
			return errors.New("登出跳转白名单非法: " + err.Error())
		}
		req.PostLogoutURIs = strings.Join(plist, ",")
	}
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
	// 应用级群号校验：为空表示继承全局设置，非空时必须是纯数字。
	if req.TargetGroupID != "" {
		if _, err := strconv.ParseUint(req.TargetGroupID, 10, 64); err != nil {
			return errors.New("QQ 群号必须是纯数字")
		}
	}
	return nil
}

const clientColumns = `c.client_id, c.client_name, c.redirect_uris,
	COALESCE(c.post_logout_redirect_uris, ''), c.created_at,
	COALESCE(c.display_name, ''), COALESCE(c.background_url, ''),
	COALESCE(c.prompt_text, ''), COALESCE(c.custom_css, ''),
	COALESCE(c.target_group_id, ''), COALESCE(c.issuer_slug, ''),
	COALESCE((SELECT kid FROM tenant_keys WHERE slug = c.issuer_slug AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1), '')`

func handleListClients(w http.ResponseWriter, r *http.Request) {
	rows, err := database.DB.Query("SELECT " + clientColumns + " FROM oidc_clients c ORDER BY c.created_at")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	defer rows.Close()

	clients := []ClientInfo{}
	for rows.Next() {
		var c ClientInfo
		if err := rows.Scan(&c.ClientID, &c.ClientName, &c.RedirectURIs, &c.PostLogoutURIs, &c.CreatedAt,
			&c.DisplayName, &c.BackgroundURL, &c.PromptText, &c.CustomCSS,
			&c.TargetGroupID, &c.IssuerSlug, &c.Kid); err != nil {
			continue
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[管理后台] 查询客户端列表异常: %v", err)
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
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
		if u.User != nil {
			return nil, fmt.Errorf("回调地址不能包含账号信息 (userinfo): %s", uri)
		}
		if strings.Contains(uri, "\\") || strings.Contains(strings.ToLower(uri), "%5c") {
			return nil, fmt.Errorf("回调地址不能包含反斜杠: %s", uri)
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

	// issuer_slug 必填且创建后不可变：它决定该应用的 Issuer
	// (https://host/{slug})，改动会让下游配置失效。
	slug := strings.ToLower(strings.TrimSpace(req.IssuerSlug))
	if slug == "" {
		writeError(w, http.StatusBadRequest, "Issuer 标识 (issuer_slug) 不能为空")
		return
	}
	if err := database.ValidateSlug(slug); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if taken, err := database.SlugTaken(slug); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	} else if taken {
		writeError(w, http.StatusBadRequest, "Issuer 标识已被占用，请换一个: "+slug)
		return
	}

	clientID := generateClientID()
	clientSecret := generateClientSecret()
	if clientID == "" || clientSecret == "" {
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[管理后台] 生成 client_secret 哈希失败: %v", err)
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	secretHash := string(hashed)

	_, err = database.WriteDB.Exec(`
		INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris,
			post_logout_redirect_uris, display_name, background_url, prompt_text, custom_css,
			target_group_id, issuer_slug)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		clientID, secretHash, req.ClientName, req.RedirectURIs, req.PostLogoutURIs,
		req.DisplayName, req.BackgroundURL, req.PromptText, req.CustomCSS, req.TargetGroupID, slug)
	if err != nil {
		log.Printf("[管理后台] 创建客户端失败: %v", err)
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	database.InvalidateClientBranding(clientID)

	log.Printf("[管理后台] 创建 OIDC 客户端 %q (%s, issuer_slug=%s) ip=%s", req.ClientName, clientID, slug, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"client_name":   req.ClientName,
		"issuer_slug":   slug,
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
			post_logout_redirect_uris = ?,
			display_name = ?, background_url = ?, prompt_text = ?, custom_css = ?,
			target_group_id = ?
		WHERE client_id = ?`,
		req.ClientName, req.RedirectURIs, req.PostLogoutURIs,
		req.DisplayName, req.BackgroundURL, req.PromptText, req.CustomCSS, req.TargetGroupID, id)
	if err != nil {
		log.Printf("[管理后台] 更新客户端 %s 失败: %v", id, err)
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "客户端不存在或已被移除")
		return
	}
	database.InvalidateClientBranding(id)

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
	database.InvalidateClientBranding(id)

	log.Printf("[管理后台] 删除 OIDC 客户端 %s ip=%s", id, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRotateClientKey 轮换某应用（issuer_slug）的签名密钥：旧密钥进入
// 宽限期（仍出现在 JWKS 中），新密钥立即生效用于后续签发。返回新 kid。
func handleRotateClientKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Bad request")
		return
	}
	slug, ok := database.SlugForClient(id)
	if !ok {
		writeError(w, http.StatusNotFound, "客户端不存在或未分配 Issuer 标识")
		return
	}
	newKid, err := oidc.RotateTenantKey(slug)
	if err != nil {
		log.Printf("[管理后台] 轮换客户端 %s (slug=%s) 密钥失败: %v", id, slug, err)
		writeError(w, http.StatusInternalServerError, "密钥轮换失败")
		return
	}
	log.Printf("[管理后台] 轮换 OIDC 客户端 %s (slug=%s) 签名密钥，新 kid=%s ip=%s", id, slug, newKid, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "kid": newKid})
}

// ---- 鉴权与工具 ----

const adminSessionCookie = "admin_token"

// setAdminSessionCookie 把管理会话写进 HttpOnly Cookie：JS 读不到，
// 同源 XSS 无法像读 localStorage 那样直接把会话偷走复用。Secure
// 只在 HTTPS 时加（直连 http 部署下 Secure Cookie 根本不会被
// 浏览器发回，管理台会登录不上）；SameSite=Lax 让跨站 POST/fetch
// 默认不带 Cookie，再叠加 authMiddleware 的同源校验。
func setAdminSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(adminSessionTTL / time.Second),
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAdminSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// requestIsHTTPS 判定当前请求是否走 HTTPS：直连 TLS，或经可信反代
// 透传 X-Forwarded-Proto: https。直连公网时该头可伪造，不采信。
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if r.Header.Get("X-Forwarded-Proto") != "https" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && isTrustedProxyAddr(ip)
}

// adminTokenFromRequest 优先读 Bearer（非浏览器 API 客户端与旧测试），
// 其次读 HttpOnly Cookie（浏览器管理台）。Cookie 路径返回 fromCookie，
// 供 authMiddleware 对 Cookie 会话做额外的同源校验。
func adminTokenFromRequest(r *http.Request) (token string, fromCookie bool) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		if t := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")); t != "" {
			return t, false
		}
	}
	if c, err := r.Cookie(adminSessionCookie); err == nil && strings.TrimSpace(c.Value) != "" {
		return c.Value, true
	}
	return "", false
}

// sameOriginRequest 校验 Origin/Referer 是否同源：Cookie 会话下，
// 跨站请求即使带上 Cookie 也会被挡。两个头都不带时（同源 fetch
// 默认可能不带 Origin）放行，SameSite=Lax 已挡住跨站写请求。
func sameOriginRequest(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		u, err := url.Parse(origin)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		u, err := url.Parse(referer)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	}
	return true
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, fromCookie := adminTokenFromRequest(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		if fromCookie && !sameOriginRequest(r) {
			writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}

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

func handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	qqFilter := q.Get("qq")
	ipFilter := q.Get("ip")

	limit := 50
	if lStr := q.Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}

	offset := 0
	if oStr := q.Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}

	logs, total, err := database.ListAuditLogs(qqFilter, ipFilter, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "获取审计日志失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   logs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
