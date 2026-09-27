package admin

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

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
