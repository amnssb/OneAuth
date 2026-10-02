package session

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oneauth/internal/database"
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
			s, err := m.CreateSession("client", "http://localhost/cb", "state", "", "87654321", 60)
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
		s, err := m.CreateSession("client", "http://localhost/cb", "", "", "87654321", 60)
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
				if _, ok := m.VerifyCode("qq", s.VerifyCode, "10001", "87654321"); ok {
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
	s, err := m.CreateSession("client", "http://localhost/cb", "", "", "87654321", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	m.mu.Lock()
	s.ExpiresAt = time.Now().Add(-time.Second)
	m.mu.Unlock()

	if _, ok := m.VerifyCode("qq", s.VerifyCode, "10001", "87654321"); ok {
		t.Fatal("expired code must not verify")
	}
}

// 群绑定回归：验证码只能在会话绑定的群内核销 —— 错误群拒绝且不消耗
// 验证码；未绑定群（GroupID 为空）的会话一律拒绝核销。
func TestVerifyCodeGroupBinding(t *testing.T) {
	m := NewManager()
	s, err := m.CreateSession("client", "http://localhost/cb", "", "", "111111", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	if _, ok := m.VerifyCode("qq", s.VerifyCode, "10001", "999999"); ok {
		t.Fatal("code from a wrong group must not verify")
	}
	// 被错误群拒绝后，验证码必须仍然可用（未被消耗）。
	if _, ok := m.VerifyCode("qq", s.VerifyCode, "10001", "111111"); !ok {
		t.Fatal("code must remain verifiable in its bound group")
	}

	nogroup, err := m.CreateSession("client", "http://localhost/cb", "", "", "", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if _, ok := m.VerifyCode("qq", nogroup.VerifyCode, "10001", "111111"); ok {
		t.Fatal("session without a bound group must not verify")
	}
}

// 累计计数回归：CreatedTotal/VerifiedTotal 自启动只增不减，被拒绝的
// 核销（错误群）不得计入 VerifiedTotal。
func TestStatsCumulativeCounters(t *testing.T) {
	m := NewManager()
	s1, err := m.CreateSession("client", "http://localhost/cb", "", "", "111111", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	s2, err := m.CreateSession("client", "http://localhost/cb", "", "", "222222", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	_ = s2 // 仅需其存在于管理器中参与快照计数

	if _, ok := m.VerifyCode("qq", s1.VerifyCode, "10001", "999999"); ok {
		t.Fatal("wrong-group verify must fail")
	}
	if _, ok := m.VerifyCode("qq", s1.VerifyCode, "10001", "111111"); !ok {
		t.Fatal("verify failed")
	}

	st := m.Stats()
	if st.CreatedTotal != 2 {
		t.Fatalf("CreatedTotal = %d, want 2", st.CreatedTotal)
	}
	if st.VerifiedTotal != 1 {
		t.Fatalf("VerifiedTotal = %d, want 1", st.VerifiedTotal)
	}
	// 实时快照：s1 已核销待回调，s2 仍待核销。
	if st.Pending != 1 || st.Verified != 1 || st.Total != 2 {
		t.Fatalf("snapshot = %+v, want pending=1 verified=1 total=2", st)
	}
}

// SSE 等待路径：核销后 NotifyChan 必须被关闭以唤醒等待方。
func TestNotifyChanClosedOnVerify(t *testing.T) {
	m := NewManager()
	s, err := m.CreateSession("client", "http://localhost/cb", "", "", "87654321", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		<-s.NotifyChan
		close(done)
	}()

	if _, ok := m.VerifyCode("qq", s.VerifyCode, "10001", "87654321"); !ok {
		t.Fatal("verify failed")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("NotifyChan was not closed on verify")
	}
}

// 跨重启/无感更新：会话保存至数据库并恢复测试
func TestSaveAndRestoreStateDB(t *testing.T) {
	db, err := database.InitDB(t.TempDir() + "/session_test.db")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()
	defer database.WriteDB.Close()

	m1 := NewManager()
	s1, err := m1.CreateSession("client1", "http://localhost/cb1", "state1", "challenge1", "8888", 60)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 核销 s1
	if _, ok := m1.VerifyCode("qq", s1.VerifyCode, "10001", "8888"); !ok {
		t.Fatalf("VerifyCode failed")
	}

	// 创建未核销的 s2
	s2, err := m1.CreateSession("client2", "http://localhost/cb2", "state2", "challenge2", "8888", 60)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 保存状态到数据库
	if err := m1.SaveStateToDB(); err != nil {
		t.Fatalf("SaveStateToDB failed: %v", err)
	}

	// 模拟新进程启动恢复会话
	m2 := NewManager()
	count, err := m2.RestoreStateFromDB()
	if err != nil {
		t.Fatalf("RestoreStateFromDB failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 restored sessions, got %d", count)
	}

	// 验证 s1 恢复后为 Verified 状态
	restored1, exists := m2.GetSession(s1.SessionID)
	if !exists {
		t.Fatalf("s1 not found after restore")
	}
	if restored1.Status != StatusVerified {
		t.Fatalf("expected s1 status VERIFIED, got %s", restored1.Status)
	}

	// 验证 s2 恢复后可以通过 codeIndex 正常核销（用户无感）
	verified2, ok := m2.VerifyCode("qq", s2.VerifyCode, "10002", "8888")
	if !ok {
		t.Fatalf("failed to verify s2 after restore")
	}
	if verified2.UserID != "10002" {
		t.Fatalf("expected user 10002, got %s", verified2.UserID)
	}
}
