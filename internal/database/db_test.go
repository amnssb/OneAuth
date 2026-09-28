package database

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
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

// v3 迁移：存量应用（无 issuer_slug）应被自动回填合法且唯一的 slug；
// 二次运行 migrate 必须幂等（不改动已分配的 slug）。
func TestIssuerSlugBackfillIdempotent(t *testing.T) {
	initTestDB(t)

	// 插入两个“存量”应用（issuer_slug 为空），其中一个 client_id 会规整成
	// 保留字，验证冲突/保留字规避逻辑。
	if _, err := WriteDB.Exec(
		"INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug) VALUES ('demo', 'h', 'n', 'u', NULL)",
	); err != nil {
		t.Fatalf("seed client 1: %v", err)
	}
	if _, err := WriteDB.Exec(
		"INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug) VALUES ('oa_Team01', 'h', 'n', 'u', NULL)",
	); err != nil {
		t.Fatalf("seed client 2: %v", err)
	}

	if err := backfillIssuerSlugs(); err != nil {
		t.Fatalf("first backfill: %v", err)
	}

	slug1, ok1 := SlugForClient("demo")
	slug2, ok2 := SlugForClient("oa_Team01")
	if !ok1 || !ok2 {
		t.Fatalf("both clients must have slugs, got %q(%v) %q(%v)", slug1, ok1, slug2, ok2)
	}
	if reservedSlugs[slug1] {
		t.Fatalf("client 'demo' must not get a reserved slug, got %q", slug1)
	}
	if slug1 == slug2 {
		t.Fatalf("slugs must be unique, both got %q", slug1)
	}
	for _, s := range []string{slug1, slug2} {
		if !slugPattern.MatchString(s) {
			t.Fatalf("slug %q does not match pattern", s)
		}
	}

	// 幂等：再次回填不得改变已分配的 slug。
	if err := backfillIssuerSlugs(); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	slug1b, _ := SlugForClient("demo")
	slug2b, _ := SlugForClient("oa_Team01")
	if slug1b != slug1 || slug2b != slug2 {
		t.Fatalf("backfill not idempotent: (%q,%q) -> (%q,%q)", slug1, slug2, slug1b, slug2b)
	}
}

// ValidateSlug 覆盖格式、保留字与合法值。
func TestValidateSlug(t *testing.T) {
	cases := []struct {
		slug    string
		wantErr bool
	}{
		{"acme", false},
		{"gitea-team", false},
		{"a1", false},
		{"a", true},           // 太短
		{"-abc", true},        // 以短横线开头
		{"Abc", true},         // 大写
		{"admin", true},       // 保留字
		{"demo", true},        // 保留字
		{"with space", true},  // 空格
		{"toolongtoolongtoolongtoolongtoolong", true}, // 超长
	}
	for _, tc := range cases {
		err := ValidateSlug(tc.slug)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ValidateSlug(%q) err=%v wantErr=%v", tc.slug, err, tc.wantErr)
		}
	}
}

// tenant_keys CRUD：插入在用密钥、退休后仍在宽限期内可见、清理后消失。
func TestTenantKeyLifecycle(t *testing.T) {
	initTestDB(t)

	grace := time.Hour
	if err := InsertTenantKey("acme", "kid-1", "PEM1"); err != nil {
		t.Fatalf("insert key: %v", err)
	}
	if row, ok := ActiveTenantKey("acme"); !ok || row.Kid != "kid-1" {
		t.Fatalf("active key mismatch: %+v ok=%v", row, ok)
	}

	// 退休旧 key + 插入新 key
	if err := RetireActiveTenantKeys("acme"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := InsertTenantKey("acme", "kid-2", "PEM2"); err != nil {
		t.Fatalf("insert new key: %v", err)
	}
	if row, ok := ActiveTenantKey("acme"); !ok || row.Kid != "kid-2" {
		t.Fatalf("active should be kid-2: %+v ok=%v", row, ok)
	}

	// 宽限期内 JWKS 两把 key 都在
	keys, err := TenantJWKSKeys("acme", grace)
	if err != nil {
		t.Fatalf("jwks keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys within grace, got %d", len(keys))
	}

	// 把 kid-1 退休时间推到宽限期外并清理
	past := time.Now().Add(-2 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	if _, err := WriteDB.Exec("UPDATE tenant_keys SET retired_at = ? WHERE slug='acme' AND kid='kid-1'", past); err != nil {
		t.Fatalf("age kid-1: %v", err)
	}
	if err := PurgeExpiredTenantKeys("acme", grace); err != nil {
		t.Fatalf("purge: %v", err)
	}
	keys, _ = TenantJWKSKeys("acme", grace)
	if len(keys) != 1 || keys[0].Kid != "kid-2" {
		t.Fatalf("only kid-2 should remain, got %+v", keys)
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
