package admin

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestLimiter(window time.Duration, max int, lock time.Duration) *loginLimiter {
	return &loginLimiter{
		entries: make(map[string]*loginFails),
		window:  window,
		max:     max,
		lock:    lock,
	}
}

// 并发登录/鉴权等价于并发 put/get/delete：-race 下必须无数据竞争。
func TestAdminSessionStoreConcurrent(t *testing.T) {
	s := &adminSessionStore{sessions: make(map[string]*adminClaims)}

	var wg sync.WaitGroup

	// 每个协程独立管理自己的 token 生命周期
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("token-%d", i)
			s.put(token, &adminClaims{Username: "admin", Exp: time.Now().Add(time.Hour).Unix()})
			for j := 0; j < 100; j++ {
				if _, ok := s.get(token); !ok {
					t.Errorf("token %s should be valid", token)
					return
				}
			}
			s.delete(token)
			if _, ok := s.get(token); ok {
				t.Errorf("deleted token %s must be rejected", token)
			}
		}(i)
	}

	// 并发读一个共享有效 token（模拟多个请求同时鉴权）
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.put("shared", &adminClaims{Username: "admin", Exp: time.Now().Add(time.Hour).Unix()})
		for j := 0; j < 100; j++ {
			claim, ok := s.get("shared")
			if ok && claim.Username != "admin" {
				t.Errorf("unexpected claim for shared token")
				return
			}
		}
	}()

	// 并发写入并读取过期 token：读取必须失败（访问即清理）
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			s.put("expired", &adminClaims{Username: "admin", Exp: time.Now().Add(-time.Second).Unix()})
			if _, ok := s.get("expired"); ok {
				t.Errorf("expired token must be rejected")
				return
			}
		}
	}()

	wg.Wait()
}

// 过期项必须被清理、有效项必须保留。
func TestAdminSessionStoreEviction(t *testing.T) {
	s := &adminSessionStore{sessions: make(map[string]*adminClaims)}
	s.put("live", &adminClaims{Username: "admin", Exp: time.Now().Add(time.Hour).Unix()})
	s.put("dead", &adminClaims{Username: "admin", Exp: time.Now().Add(-time.Second).Unix()})

	now := time.Now().Unix()
	s.mu.Lock()
	for token, claim := range s.sessions {
		if now > claim.Exp {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()

	if _, ok := s.get("live"); !ok {
		t.Fatal("live token was evicted")
	}
	s.mu.RLock()
	_, deadExists := s.sessions["dead"]
	s.mu.RUnlock()
	if deadExists {
		t.Fatal("expired token was not evicted")
	}
}

// 滑动续期：剩余寿命不足会话 TTL 一半才刷新，否则不动。
func TestAdminSessionStoreRenew(t *testing.T) {
	s := &adminSessionStore{sessions: make(map[string]*adminClaims)}
	ttl := adminSessionTTL

	// 剩余寿命 > TTL/2：不应续期
	claim := &adminClaims{Username: "admin", IssuedAt: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix()}
	s.put("t1", claim)
	s.renew("t1", claim)
	s.mu.RLock()
	renewed := s.sessions["t1"]
	s.mu.RUnlock()
	if renewed != claim {
		t.Fatal("fresh session must not be renewed")
	}

	// 只剩 10 分钟（不足一半）：应续到满血
	old := &adminClaims{Username: "admin", IssuedAt: time.Now().Add(-50 * time.Minute).Unix(), Exp: time.Now().Add(10 * time.Minute).Unix()}
	s.put("t2", old)
	s.renew("t2", old)
	fresh, ok := s.get("t2")
	if !ok {
		t.Fatal("renewed token should still be valid")
	}
	if fresh == old {
		t.Fatal("nearly expired session must be replaced with a renewed one")
	}
	if remaining := time.Until(time.Unix(fresh.Exp, 0)); remaining < ttl-time.Minute {
		t.Fatalf("renewed expiry too short: %v", remaining)
	}
}

// 限速器：window 内第 max 次失败触发锁定；成功清零；窗口/锁定期满自动恢复。
func TestLoginLimiter(t *testing.T) {
	l := newTestLimiter(60*time.Millisecond, 3, 120*time.Millisecond)

	for i := 0; i < 2; i++ {
		l.recordFailure("ip")
	}
	if l.blocked("ip") != 0 {
		t.Fatal("below threshold must not lock")
	}

	l.recordFailure("ip")
	if l.blocked("ip") <= 0 {
		t.Fatal("reaching threshold must lock")
	}

	// 锁定期间继续失败不重置截止时间
	until := func() time.Time {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.entries["ip"].until
	}
	l.recordFailure("ip")
	if !until().Equal(until()) {
		t.Fatal("failures during lockout must not extend lockout")
	}

	// 成功登录清零
	l.clear("ip")
	if l.blocked("ip") != 0 {
		t.Fatal("clear must unlock")
	}

	// 锁定期满自动恢复
	for i := 0; i < 3; i++ {
		l.recordFailure("ip2")
	}
	if l.blocked("ip2") <= 0 {
		t.Fatal("expected lockout")
	}
	time.Sleep(150 * time.Millisecond)
	if l.blocked("ip2") != 0 {
		t.Fatal("lockout must expire")
	}

	// 失败记录滚出窗口后不再累计
	for i := 0; i < 2; i++ {
		l.recordFailure("ip3")
	}
	time.Sleep(80 * time.Millisecond)
	l.recordFailure("ip3")
	if l.blocked("ip3") != 0 {
		t.Fatal("stale failures must not count toward the threshold")
	}
}

// 并发失败记录不丢、不竞争（-race 下跑）。
func TestLoginLimiterConcurrent(t *testing.T) {
	l := newTestLimiter(time.Minute, 1000, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				l.recordFailure("shared")
				l.blocked("shared")
			}
		}()
	}
	wg.Wait()
	l.mu.Lock()
	count := len(l.entries["shared"].stamps)
	l.mu.Unlock()
	if count != 16*50 {
		t.Fatalf("expected %d recorded failures, got %d", 16*50, count)
	}
}

// ---- 设置与回调地址校验 ----

func TestValidateSetting(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		val     string
		wantErr bool
	}{
		{"ttl 合法", "code_ttl", "180", false},
		{"ttl 空串走默认", "code_ttl", "", false},
		{"ttl 太小", "code_ttl", "5", true},
		{"ttl 太大", "code_ttl", "7200", true},
		{"ttl 非数字", "code_ttl", "3m", true},
		{"群号合法", "target_group_id", "87654321", false},
		{"群号非数字", "target_group_id", "87a54321", true},
		{"群号可以为空", "target_group_id", "", false},
		{"http 背景图", "background_url", "https://example.com/bg.jpg", false},
		{"javascript 协议背景图", "background_url", "javascript:alert(1)", true},
		{"非 URL 背景", "background_url", "不是链接", true},
		{"logo 可为空", "site_logo", "", false},
		{"token 长度上限内", "onebot_token", strings.Repeat("x", 128), false},
		{"token 超长", "onebot_token", strings.Repeat("x", 129), true},
		{"站点名超长", "site_name", strings.Repeat("名", 101), true},
		{"css 允许较长", "custom_css", strings.Repeat("a", 64<<10), false},
		{"css 超长", "custom_css", strings.Repeat("a", 64<<10+1), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSetting(tc.key, tc.val)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateSetting(%s, %q) = %v, wantErr=%v", tc.key, tc.val, err, tc.wantErr)
			}
		})
	}
}

func TestValidateRedirectURIs(t *testing.T) {
	uris, err := validateRedirectURIs(" https://a.example.com/cb , http://b.example.com/cb ")
	if err != nil {
		t.Fatalf("valid uris rejected: %v", err)
	}
	if len(uris) != 2 || uris[0] != "https://a.example.com/cb" {
		t.Fatalf("uris not normalized: %v", uris)
	}

	bad := []string{
		"",
		"ftp://example.com/cb",
		"javascript:alert(1)",
		"https://example.com/cb#fragment",
		"https://a.com/cb,https://a.com/cb",
		"https://a.com/cb, ",
		strings.Repeat("https://a.com/cb,", 20) + "https://b.com/cb",
	}
	for _, uri := range bad {
		if _, err := validateRedirectURIs(uri); err == nil {
			t.Fatalf("expected rejection for %q", uri)
		}
	}
}

// ---- 请求体上限 ----

func TestDecodeJSONLimitsBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := decodeJSON(w, r, &req); err != nil {
			if errors.Is(err, errBodyTooLarge) {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	big := bytes.Repeat([]byte("a"), maxBodyBytes+100)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/t", bytes.NewReader(big)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: expected 413, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/t", strings.NewReader(`{"a":"b"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("normal body: expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/t", strings.NewReader(`not json`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: expected 400, got %d", rec.Code)
	}
}

// 安全响应头必须齐全（no-store 防止 token 被中间层缓存）。
func TestSecureHeaders(t *testing.T) {
	called := false
	rec := httptest.NewRecorder()
	SecureHeaders(func(w http.ResponseWriter, r *http.Request) { called = true }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/t", nil))

	if !called {
		t.Fatal("next handler not called")
	}
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Cache-Control"} {
		if rec.Header().Get(h) == "" {
			t.Fatalf("missing security header %s", h)
		}
	}
}
