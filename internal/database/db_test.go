package database

import (
	"path/filepath"
	"sync"
	"testing"
)

func initTestDB(t *testing.T) {
	t.Helper()
	db, err := InitDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	t.Cleanup(func() { db.Close(); WriteDB.Close() })
}

// 并发读写下设置：缓存与库必须保持一致，且 -race 下无数据竞争。
func TestSettingsCacheConcurrent(t *testing.T) {
	initTestDB(t)

	const writers, readers = 8, 8
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := SetSetting("site_name", "site"); err != nil {
					t.Errorf("SetSetting failed: %v", err)
					return
				}
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = GetSetting("site_name", "default")
				_ = GetSetting("missing_key", "default")
			}
		}()
	}
	wg.Wait()

	if got := GetSetting("site_name", ""); got != "site" {
		t.Fatalf("cache out of sync: got %q, want %q", got, "site")
	}
	if got := GetSetting("missing_key", "default"); got != "default" {
		t.Fatalf("missing key should fall back to default, got %q", got)
	}
}

// 写池单连接：并发写不得产生 SQLITE_BUSY 错误。
func TestConcurrentWritesNoBusy(t *testing.T) {
	initTestDB(t)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := SetSetting("code_ttl", "180"); err != nil {
				t.Errorf("concurrent write %d failed: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}
