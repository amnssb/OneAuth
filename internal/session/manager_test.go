package session

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 并发创建会话：验证码必须全局唯一，且 -race 下无数据竞争。
func TestConcurrentCreateSessionUniqueCodes(t *testing.T) {
	m := NewManager()
	const n = 200

	codes := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := m.CreateSession("client", "http://localhost/cb", "state", "", 60)
			if err != nil {
				t.Errorf("CreateSession failed: %v", err)
				return
			}
			codes[i] = s.VerifyCode
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for i, c := range codes {
		if c == "" {
			t.Fatalf("session %d got empty code", i)
		}
		if seen[c] {
			t.Fatalf("duplicate verification code generated: %s", c)
		}
		seen[c] = true
	}
}

// 并发核销同一批验证码：每个码只能被核销一次，第二次必须失败。
func TestConcurrentVerifyCodeSingleUse(t *testing.T) {
	m := NewManager()
	const n = 100

	sessions := make([]*AuthSession, n)
	for i := 0; i < n; i++ {
		s, err := m.CreateSession("client", "http://localhost/cb", "", "", 60)
		if err != nil {
			t.Fatalf("setup failed: %v", err)
		}
		sessions[i] = s
	}

	var wg sync.WaitGroup
	var successCount int64
	for i := 0; i < n; i++ {
		for attempt := 0; attempt < 4; attempt++ {
			wg.Add(1)
			go func(s *AuthSession) {
				defer wg.Done()
				if _, ok := m.VerifyCode(s.VerifyCode, "10001"); ok {
					atomic.AddInt64(&successCount, 1)
				}
			}(sessions[i])
		}
	}
	wg.Wait()

	// n 个互不相同的码，每个最多成功一次：总成功数必须恰好为 n，
	// 即每个码都成功且仅成功一次（重放核销被拒绝）。
	if atomic.LoadInt64(&successCount) != n {
		t.Fatalf("expected exactly %d successful verifies, got %d", n, successCount)
	}
}

// 过期会话核销必须失败。
func TestVerifyCodeExpired(t *testing.T) {
	m := NewManager()
	s, err := m.CreateSession("client", "http://localhost/cb", "", "", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	m.mu.Lock()
	s.ExpiresAt = time.Now().Add(-time.Second)
	m.mu.Unlock()

	if _, ok := m.VerifyCode(s.VerifyCode, "10001"); ok {
		t.Fatal("expired code must not verify")
	}
}

// SSE 等待路径：核销后 NotifyChan 必须被关闭以唤醒等待方。
func TestNotifyChanClosedOnVerify(t *testing.T) {
	m := NewManager()
	s, err := m.CreateSession("client", "http://localhost/cb", "", "", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		<-s.NotifyChan
		close(done)
	}()

	if _, ok := m.VerifyCode(s.VerifyCode, "10001"); !ok {
		t.Fatal("verify failed")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("NotifyChan was not closed on verify")
	}
}
